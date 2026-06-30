#!/usr/bin/env python
"""test_finding_ledger.py — cross-engagement finding lifecycle.

Pins the enterprise retest contract: a finding's identity is (target, CWE,
normalized-location) — STABLE across object ids and a title change — so a retest
correctly reports fixed / still-open / new / regressed."""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
LEDGER_TOOL = os.path.join(REPO, "tools", "checks", "finding_ledger.py")
sys.path.insert(0, os.path.join(REPO, "tools", "checks"))
import finding_ledger as fl  # noqa: E402

CHECKS = []


def rec(name, ok, detail=""):
    CHECKS.append(bool(ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def fj(tmp, name, target, findings):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"engagement": {"target": target, "name": name}, "findings": findings,
                   "informational": [], "leads": [], "counts": {}}, f)
    return p


def run(*args):
    r = subprocess.run([sys.executable, LEDGER_TOOL, *args], capture_output=True, text=True, timeout=30)
    return json.loads(r.stdout)


def main():
    # --- uid: identity survives object-id AND title change; differs by CWE/endpoint ---
    u1 = fl.finding_uid("acme.example", "CWE-639", "GET /api/orders/1002")
    u2 = fl.finding_uid("acme.example", "CWE-639", "GET /api/orders/5731")
    rec("uid stable across object ids (/orders/1002 == /orders/5731)", u1 == u2, f"{u1} {u2}")
    rec("uid differs by endpoint", u1 != fl.finding_uid("acme.example", "CWE-639", "GET /api/invoices/1"))
    rec("uid differs by CWE", u1 != fl.finding_uid("acme.example", "CWE-79", "GET /api/orders/1002"))
    rec("uid differs by target", u1 != fl.finding_uid("other.example", "CWE-639", "GET /api/orders/1002"))
    rec("normalize templates ids", fl.normalize_location("GET /api/orders/1002?x=1") == "/api/orders/{id}")

    tmp = tempfile.mkdtemp()
    led = os.path.join(tmp, "ledger.json")
    IDOR = {"id": "F-01", "title": "IDOR on /api/orders/{id}", "severity": "high", "cwe": "CWE-639", "location": "GET /api/orders/1002"}
    XSS = {"id": "F-02", "title": "Reflected XSS", "severity": "medium", "cwe": "CWE-79", "location": "GET /search?q="}
    SSRF = {"id": "F-04", "title": "SSRF on /fetch", "severity": "high", "cwe": "CWE-918", "location": "POST /api/fetch"}

    # --- record engagement #1 ---
    p1 = fj(tmp, "q1", "acme.example", [IDOR, XSS])
    r = run("record", p1, "--engagement", "q1", "--date", "2026-01-15", "--ledger", led)
    rec("record: 2 new", r["new"] == 2 and r["recorded"] == 2)

    # --- retest #2: IDOR persists (different object id + retitled), XSS fixed, SSRF new ---
    idor2 = {**IDOR, "title": "IDOR on order objects", "location": "GET /api/orders/5731"}
    p2 = fj(tmp, "q2", "acme.example", [idor2, SSRF])
    r = run("retest", p2, "--engagement", "q2", "--date", "2026-04-15", "--ledger", led)
    rec("retest: XSS -> fixed", r["summary"]["fixed"] == 1 and "XSS" in r["fixed"][0]["title"])
    rec("retest: IDOR -> still_open (survived id+title change)", r["summary"]["still_open"] == 1 and r["still_open"][0]["cwe"] == "CWE-639")
    rec("retest: SSRF -> new", r["summary"]["new"] == 1 and r["new"][0]["cwe"] == "CWE-918")

    # --- retest #3: the FIXED XSS comes back -> regressed ---
    p3 = fj(tmp, "q3", "acme.example", [XSS])
    r = run("retest", p3, "--engagement", "q3", "--date", "2026-07-15", "--ledger", led)
    rec("retest: a fixed finding that returns -> regressed", r["summary"]["regressed"] == 1)

    # --- status reflects the ledger (3 distinct findings ever: IDOR, XSS, SSRF) ---
    st = run("status", "--target", "acme.example", "--ledger", led)
    rec("status totals all distinct tracked findings", st["total"] == 3, str(st.get("counts")))

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
