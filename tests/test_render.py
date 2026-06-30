#!/usr/bin/env python
"""test_render.py — render_report.py chokepoint + findings->report contract.

There was NO test exercising render_report.py, so the v0.3.0 render chokepoint
regression (refuse-to-render on advisory PII) shipped unnoticed. This pins the
v0.3.1 behavior so it cannot regress:
  - clean findings.json RENDERS (exit 0, report.md written)
  - advisory PII (an email) RENDERS, not refused (exit 0)        [the v0.3.0 regression]
  - a SECRET in findings.json REFUSES the render (exit 4)        [security guarantee]
  - a legacy/blank evidence_index row is caught by finding_schema (exit 1)  [blank-row class]

Contains a synthetic credential fixture (no real material): redact-allow-file.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
RENDER = os.path.join(REPO, "tools", "report-render", "render_report.py")
SCHEMA = os.path.join(REPO, "tools", "checks", "finding_schema.py")

CHECKS = []


def rec(name, ok, detail=""):
    CHECKS.append(bool(ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def base(desc="An IDOR lets a low-priv user read another tenant's order."):
    return {
        "engagement": {"name": "lab", "target": "127.0.0.1", "date": "2026-01-01"},
        "summary": "Synthetic render-test fixture. 1 confirmed (1 High), 0 informational, 0 leads.",
        "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        "findings": [{
            "id": "F-01", "title": "IDOR on /api/orders/{id}", "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "cvss_score": 7.1,
            "cwe": "CWE-639", "location": "/api/orders/{id}", "description": desc,
            "reproduction": ["GET /api/orders/123 as user B -> 200 with user A's order"],
            "remediation": "Enforce object-level authorization server-side.",
            "verification": "Reproduced from a clean session by the verifier.",
            "evidence": ["idor.http"], "validation_status": "verified",
        }],
        "informational": [], "leads": [],
        "evidence_index": [{"file": "idor.http", "contents": "request/response capture", "ref": "F-01"}],
    }


def write(obj):
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "evidence"), exist_ok=True)
    with open(os.path.join(d, "evidence", "idor.http"), "w", encoding="utf-8") as f:
        f.write("GET /api/orders/123 HTTP/1.1\n\nHTTP/1.1 200 OK\n{\"order\": 123}\n")
    p = os.path.join(d, "findings.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    return d, p


def render(p):
    return subprocess.run([sys.executable, RENDER, p, "--all"],
                          capture_output=True, text=True, timeout=60)


def schema(p):
    return subprocess.run([sys.executable, SCHEMA, p], capture_output=True, text=True, timeout=30)


def main():
    # 1. clean render -> exit 0, report.md written
    d, p = write(base())
    r = render(p)
    rec("clean findings render (exit 0)", r.returncode == 0, (r.stdout + r.stderr)[-160:])
    rec("report.md written", os.path.exists(os.path.join(d, "report.md")))
    md = open(os.path.join(d, "report.md"), encoding="utf-8").read() if os.path.exists(os.path.join(d, "report.md")) else ""
    rec("finding_uid stamped into the report (Tracking ID)", "Tracking ID" in md)

    # a findings.json carrying a `retest` block renders the Retest / remediation delta section
    rt = base()
    rt["retest"] = {"date": "2026-04-15", "summary": {"fixed": 1, "still_open": 1, "new": 0, "regressed": 0},
                    "fixed": [{"uid": "abc123def456", "title": "Old reflected XSS", "severity": "medium"}],
                    "still_open": [], "new": [], "regressed": []}
    dR, pR = write(rt)
    render(pR)
    mdR = open(os.path.join(dR, "report.md"), encoding="utf-8").read() if os.path.exists(os.path.join(dR, "report.md")) else ""
    rec("retest block -> Retest/Delta section rendered", "Retest / remediation delta" in mdR and "Old reflected XSS" in mdR)

    # 2. advisory PII (email) RENDERS — the v0.3.0 regression (refused on PII) must stay fixed
    d2, p2 = write(base(desc="Contact the owner at security-reports@example.com to remediate."))
    r2 = render(p2)
    rec("advisory PII (email) RENDERS, not refused (exit 0)",
        r2.returncode == 0 and os.path.exists(os.path.join(d2, "report.md")), f"rc={r2.returncode}")

    # 3. a SECRET still REFUSES — the security guarantee must hold
    d3, p3 = write(base(desc="leaked Authorization: Bearer abcDEF0123456789ghiJKLmnoPQR here."))
    r3 = render(p3)
    rec("credential in findings.json REFUSES render (exit 4)",
        r3.returncode == 4 and "REFUSING" in r3.stdout, f"rc={r3.returncode}")
    rec("refused render did NOT write report.md", not os.path.exists(os.path.join(d3, "report.md")))

    # 4. legacy/blank evidence_index row -> finding_schema errors (the blank-appendix-row class)
    obj = base()
    obj["evidence_index"] = [{"ref": "F-01", "path": "idor.http", "desc": "capture"}]  # legacy keys, no 'file'
    d4, p4 = write(obj)
    r4 = schema(p4)
    try:
        out = json.loads(r4.stdout)
        caught = any("evidence_index" in e and "BLANK" in e for e in out.get("errors", []))
    except Exception:
        caught = False
    rec("finding_schema catches blank/legacy evidence_index row (exit 1)",
        r4.returncode == 1 and caught, f"rc={r4.returncode}")

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
