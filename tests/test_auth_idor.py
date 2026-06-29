#!/usr/bin/env python
"""test_auth_idor.py — the authenticated IDOR 4-cell oracle (auth_request --idor).

Covers the post-login surface the black-box suite can't reach: with seeded
out-of-tree roles + session cookies, the oracle must CONFIRM IDOR on an endpoint
with no ownership check (other role sees the owner's canary; anon does not; differs
from the bogus-id control) and return NO-IDOR on the ownership-enforced endpoint.
Credentials live in a temp PENTEST_AUTH_HOME, never the repo — exactly as a real
engagement requires.
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
    """Write roles.json + session cookie jars under an out-of-tree auth home."""
    eng_dir = os.path.join(home, engagement)
    sess = os.path.join(eng_dir, "sessions")
    os.makedirs(sess, exist_ok=True)
    roles = {"roles": [
        {"role": "alice", "type": "form", "identity_url": f"{base}/me", "identity_marker": "alice"},
        {"role": "bob", "type": "form", "identity_url": f"{base}/me", "identity_marker": "bob"},
    ]}
    with open(os.path.join(eng_dir, "roles.json"), "w", encoding="utf-8") as f:
        json.dump(roles, f)
    for user in ("alice", "bob"):
        with open(os.path.join(sess, f"{user}.cookie"), "w", encoding="utf-8") as f:
            # Netscape format: host-only (flag FALSE) + a far-future expiry — expiry 0 is a
            # session cookie that load() drops, and flag TRUE needs a dotted domain (invalid for an IP).
            f.write("# Netscape HTTP Cookie File\n")
            f.write("\t".join(["127.0.0.1", "FALSE", "/", "FALSE", "2000000000", "session", user]) + "\n")


def run_idor(env, engagement, url):
    r = subprocess.run([sys.executable, AUTH_REQ, "--engagement", engagement, "--idor",
                        "--owner", "alice", "--other", "bob", "--canary", "ALICE_CANARY_7f3a",
                        "--insecure", url], capture_output=True, text=True, timeout=60, env=env)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"_err": r.stdout[-400:] + "\n--STDERR--\n" + r.stderr[-400:]}


def main():
    home = tempfile.mkdtemp()
    env = {**os.environ, "PENTEST_AUTH_HOME": home}
    eng = "authtest"
    srv, base = start_lab()
    try:
        seed_auth(home, eng, base)

        # sanity: the seeded sessions are live (identity oracle reachable)
        vuln = run_idor(env, eng, f"{base}/orders/9")
        owner_valid = vuln.get("matrix", {}).get("owner", {}).get("session_valid")
        rec("seeded alice session is live (identity_marker present)", owner_valid is True,
            vuln.get("_err", "") or json.dumps(vuln.get("matrix", {}).get("owner", {}))[:120])

        # TP: ownership-free endpoint -> IDOR confirmed
        rec("IDOR confirmed on the unprotected /orders/{id}", vuln.get("verdict") == "idor-confirmed",
            vuln.get("verdict", vuln.get("_err", "")))

        # FP-rejection: ownership-enforced endpoint -> no IDOR (bob gets 403)
        secure = run_idor(env, eng, f"{base}/orders-secure/9")
        rec("NO IDOR on the ownership-enforced /orders-secure/{id}", secure.get("verdict") == "no-idor",
            secure.get("verdict", secure.get("_err", "")))
    finally:
        srv.shutdown()

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
