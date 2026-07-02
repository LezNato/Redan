#!/usr/bin/env python
"""test_flow_map.py — the business-process/authz-matrix skeleton is built correctly.

flow_map is a MAPPER (an oracle skeleton, no disposition), so this is a STRUCTURAL test:
crawling a small multi-step lab surface, it must detect the flows, classify the anon access
matrix (a gated sensitive path as gated), and map param names to the right candidate
invariants — the raw material the recon/mapper agent annotates into the intent oracle.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TOOLS = os.path.join(REPO, "tools", "checks")
sys.path.insert(0, HERE)
from lab_server import start_lab  # noqa: E402

CHECKS = []


def rec(name, ok, detail=""):
    CHECKS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def main():
    srv, base = start_lab()
    try:
        r = subprocess.run([sys.executable, os.path.join(TOOLS, "flow_map.py"),
                            f"{base}/shop", "--max-pages", "20", "--depth", "2"],
                           capture_output=True, text=True, timeout=90)
        try:
            res = json.loads(r.stdout)
        except Exception:
            res = {"_err": r.stdout[-400:] + "\n--STDERR--\n" + r.stderr[-400:]}

        flows = {f.get("name") for f in res.get("flows", [])}
        rec("flow_map: detects the checkout flow", "checkout" in flows, str(flows) or res.get("_err", ""))
        rec("flow_map: detects the registration flow", "registration" in flows, str(flows))

        inv = {i.get("type") for i in res.get("candidate_invariants", [])}
        inv_params = {i.get("param") for i in res.get("candidate_invariants", [])}
        rec("flow_map: price param -> server-authoritative-price invariant", "server-authoritative-price" in inv, str(inv))
        rec("flow_map: coupon param -> single-use-code invariant", "single-use-code" in inv, str(inv))
        # token-boundary matching: account_id -> object-ownership (NOT stolen by qty's 'count' substring)
        rec("flow_map: account_id -> object-ownership (token match, not sane-quantity)",
            "object-ownership" in inv, str(inv))
        # FP-reject: a benign auth/UX param must NOT be misclassified as a business invariant
        rec("flow_map FP-reject: benign 'remember' is not classified as an invariant",
            "remember" not in inv_params, str(inv_params))

        # --- endpoint-level invariants: SoD on an approval step, append-only on an audit record ---
        sod_locs = {i.get("location") for i in res.get("candidate_invariants", [])
                    if i.get("type") == "separation-of-duties"}
        audit_locs = {i.get("location") for i in res.get("candidate_invariants", [])
                      if i.get("type") == "append-only"}
        rec("flow_map: /order/9/approve -> separation-of-duties candidate (approval step)",
            "separation-of-duties" in inv and any("/order/9/approve" == l for l in sod_locs), str(sod_locs))
        rec("flow_map: /approve/9 -> separation-of-duties candidate (verb-first RPC on a resource)",
            any("/approve/9" == l for l in sod_locs), str(sod_locs))
        rec("flow_map: /admin/auditlog -> append-only candidate (audit record)",
            "append-only" in inv and any("auditlog" in (l or "") for l in audit_locs), str(audit_locs))
        # FP-reject: an email-verification step is NOT two-party approval (verify not an approval token)
        rec("flow_map FP-reject: /verify is not classified separation-of-duties",
            not any("/verify" in (l or "") for l in sod_locs), str(sod_locs))
        # FP-reject: self-publish (CMS) is single-actor, not two-party SoD ('publish' dropped)
        rec("flow_map FP-reject: /blog/9/publish is not classified separation-of-duties",
            not any("publish" in (l or "") for l in sod_locs), str(sod_locs))
        # FP-reject: OAuth self-consent is not two-party approval ('authorize' dropped)
        rec("flow_map FP-reject: /oauth/authorize is not classified separation-of-duties",
            not any("authorize" in (l or "") for l in sod_locs), str(sod_locs))
        # FP-reject: 'login' must not trip the audit 'log' token (token-boundary matching)
        rec("flow_map FP-reject: /login is not classified append-only (login != log)",
            not any("/login" in (l or "") for l in audit_locs), str(audit_locs))
        # FP-reject: a public read-only /changelog page is not an audit record ('changelog' dropped)
        rec("flow_map FP-reject: /changelog is not classified append-only",
            not any("changelog" in (l or "") for l in audit_locs), str(audit_locs))
        # each candidate invariant is tagged by basis (param-name vs endpoint-derived)
        bases = {i.get("basis") for i in res.get("candidate_invariants", [])}
        rec("flow_map: candidate invariants tagged by basis (param + endpoint)",
            "param" in bases and "endpoint" in bases, str(bases))

        am = {m.get("path"): m for m in res.get("access_matrix", [])}
        ao = am.get("/admin-orders", {})
        rec("flow_map: /admin-orders classified gated + sensitive",
            ao.get("anon_class") == "gated" and ao.get("sensitive") is True, str(ao))
        rec("flow_map: gated path surfaced as a bypass target",
            "/admin-orders" in res.get("hints", {}).get("gated_paths_to_test_bypass", []),
            str(res.get("hints")))
        # FP-reject: a benign public path stays open + out of the prioritized bypass hints
        rec("flow_map FP-reject: benign public /shop stays open + not a bypass target",
            am.get("/shop", {}).get("anon_class") == "open"
            and "/shop" not in res.get("hints", {}).get("gated_paths_to_test_bypass", []),
            str(am.get("/shop")))

        rec("flow_map: the skeleton is marked provisional (needs mapper annotation)",
            res.get("provisional") is True, str(res.get("provisional")))
        rec("flow_map: emits a pre-seeded expected_authz scaffold (producer shape matches consumers)",
            isinstance(res.get("expected_authz"), list), str(type(res.get("expected_authz"))))
        # oracle guarantee: a MAPPER asserts nothing — no verdict/disposition key anywhere
        rec("flow_map: carries NO verdict/disposition (asserts nothing, stays an oracle)",
            not any(k in res for k in ("disposition", "verdict", "confirmed", "findings", "finding"))
            and all(("disposition" not in m and "verdict" not in m) for m in res.get("access_matrix", [])),
            str([k for k in ("disposition", "verdict", "confirmed", "findings") if k in res]))
    finally:
        srv.shutdown()

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
