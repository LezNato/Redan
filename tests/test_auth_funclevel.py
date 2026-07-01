#!/usr/bin/env python
"""test_auth_funclevel.py — auth_request --funclevel discipline (the "200 ≠ reached" redesign).

Function-level access control must not be graded on status alone. With a seeded low-priv session:
  * TP (confirmed): /admin-panel returns real admin content carrying the --canary marker to any
    logged-in user (anon 401) -> verdict funclevel-broken (a high finding needs POSITIVE evidence).
  * LEAD: the same reach WITHOUT a canary -> funclevel-lead (a lead, not a hard finding).
  * FP-reject: /admin-softdeny (200 "Access denied") and /admin-softdeny2 (200 "You do not have
    permission" — an OLD-regex miss) -> funclevel-enforced (the soft-deny filter, broadened).
  * public: /public-info returns an identical 200 to anon+low-priv -> a public-unauth lead, NOT a
    low-priv reach (the anon-diff guard).
  * inconclusive: a dead/unverifiable low-priv session must NOT read as a clean funclevel-enforced.
Credentials live in a temp PENTEST_AUTH_HOME, never the repo.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
AUTH_REQ = os.path.join(REPO, "tools", "checks", "auth_request.py")
sys.path.insert(0, HERE)
from lab_server import start_lab  # noqa: E402

CHECKS = []


def rec(name, ok, detail=""):
    CHECKS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def seed_auth(home, engagement, base):
    eng_dir = os.path.join(home, engagement)
    sess = os.path.join(eng_dir, "sessions")
    os.makedirs(sess, exist_ok=True)
    roles = {"roles": [
        {"role": "alice", "type": "form", "identity_url": f"{base}/me", "identity_marker": "alice"},
        # deadrole: liveness will FAIL (no cookie seeded -> /me returns no matching identity)
        {"role": "deadrole", "type": "form", "identity_url": f"{base}/me", "identity_marker": "deadrole"},
    ]}
    with open(os.path.join(eng_dir, "roles.json"), "w", encoding="utf-8") as f:
        json.dump(roles, f)
    with open(os.path.join(sess, "alice.cookie"), "w", encoding="utf-8") as f:
        f.write("# Netscape HTTP Cookie File\n")
        f.write("\t".join(["127.0.0.1", "FALSE", "/", "FALSE", "2000000000", "session", "alice"]) + "\n")
    # deadrole: NO cookie file -> empty jar -> session_valid is False (the dead-session case)


def run_fl(env, engagement, role, endpoint, canary=None):
    argv = [sys.executable, AUTH_REQ, "--engagement", engagement, "--funclevel",
            "--role", role, "--endpoints", endpoint, "--insecure"]
    if canary:
        argv += ["--canary", canary]
    argv += [endpoint]   # positional url required by argparse; unused in funclevel mode
    r = subprocess.run(argv, capture_output=True, text=True, timeout=60, env=env)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"_err": r.stdout[-500:] + "\n--STDERR--\n" + r.stderr[-400:]}


def main():
    home = tempfile.mkdtemp()
    env = {**os.environ, "PENTEST_AUTH_HOME": home}
    eng = "authtest"
    srv, base = start_lab()
    try:
        seed_auth(home, eng, base)

        # TP (confirmed): canary present -> a hard funclevel-broken finding
        tp = run_fl(env, eng, "alice", f"{base}/admin-panel", canary="ADMIN_PANEL_OPEN")
        rec("funclevel TP: canary-confirmed reach -> funclevel-broken",
            tp.get("verdict") == "funclevel-broken", tp.get("verdict", tp.get("_err", "")))
        rec("funclevel TP: emits a high finding", bool(tp.get("findings")), str(tp.get("findings"))[:80])

        # LEAD: same reach without a canary is a lead, not a hard finding
        ld = run_fl(env, eng, "alice", f"{base}/admin-panel")
        rec("funclevel LEAD: a 2xx reach WITHOUT a canary is funclevel-lead (not -broken)",
            ld.get("verdict") == "funclevel-lead" and not ld.get("findings"),
            ld.get("verdict", ld.get("_err", "")))

        # FP-reject: 200 soft-deny bodies (base + broadened wording)
        f1 = run_fl(env, eng, "alice", f"{base}/admin-softdeny")
        rec("funclevel FP-reject: a 200 'Access denied' body is not broken authz",
            f1.get("verdict") == "funclevel-enforced", f1.get("verdict", f1.get("_err", "")))
        f2 = run_fl(env, eng, "alice", f"{base}/admin-softdeny2")
        rec("funclevel FP-reject: a 200 'You do not have permission' (broadened DENY_RE) is enforced",
            f2.get("verdict") == "funclevel-enforced", f2.get("verdict", f2.get("_err", "")))

        # public: identical-to-anon 200 -> public-unauth lead (anon-diff guard), NOT a low-priv reach
        pub = run_fl(env, eng, "alice", f"{base}/public-info")
        pub_cls = (pub.get("matrix") or [{}])[0].get("classification")
        rec("funclevel: an identical-to-anon 200 is a public-unauth lead (anon-diff guard)",
            pub.get("verdict") == "funclevel-lead" and pub_cls == "public-unauth",
            f"verdict={pub.get('verdict')} cls={pub_cls}")

        # inconclusive: a dead/unverifiable low-priv session must not read as a clean pass
        dead = run_fl(env, eng, "deadrole", f"{base}/admin-panel")
        rec("funclevel: a dead low-priv session -> inconclusive (never a clean funclevel-enforced)",
            dead.get("verdict") == "inconclusive", dead.get("verdict", dead.get("_err", "")))
    finally:
        srv.shutdown()

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
