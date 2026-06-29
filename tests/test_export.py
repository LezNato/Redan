#!/usr/bin/env python
"""test_export.py — export.py must populate Description from the canonical
`description` field (not the non-existent impact/detail), include reproduction,
and BLOCK when the findings.json carries credential material.

Contains a synthetic credential fixture (no real material): redact-allow-file."""
import csv
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
EXPORT = os.path.join(REPO, "tools", "report-render", "export.py")

CHECKS = []


def rec(name, ok, detail=""):
    CHECKS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


DESC = "An attacker authenticated as a low-privilege user can read other tenants' orders."
REPRO = ["GET /api/orders/123 as user B", "response returns user A's order body"]


def finding(description=DESC):
    return {
        "findings": [{
            "id": "F-01", "title": "IDOR on /api/orders/{id}", "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "cvss_score": 7.1,
            "cwe": "CWE-639", "location": "/api/orders/{id}", "description": description,
            "reproduction": REPRO, "remediation": "Enforce object-level authorization server-side.",
            "verification": "Reproduced from a clean session by the verifier.",
            "evidence": ["idor.http"], "validation_status": "verified", "disposition": "confirmed",
        }],
        "informational": [], "leads": [],
        "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    }


def write_findings(obj):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "findings.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    return d, p


def run_export(path, outdir):
    return subprocess.run([sys.executable, EXPORT, path, "--outdir", outdir],
                          capture_output=True, text=True, timeout=30)


def main():
    d, p = write_findings(finding())
    r = run_export(p, d)
    rec("export ran (clean findings)", r.returncode == 0, r.stdout[-200:] + r.stderr[-200:])

    # CSV Description column populated from canonical `description`
    csv_path = os.path.join(d, "findings.csv")
    with open(csv_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    rec("CSV Description == canonical description (not empty)",
        rows and rows[0].get("Description") == DESC, (rows[0].get("Description") if rows else ""))
    rec("CSV Reproduction populated", rows and "GET /api/orders/123" in (rows[0].get("Reproduction") or ""))

    # SARIF message == description
    with open(os.path.join(d, "findings.sarif.json"), encoding="utf-8") as f:
        sarif = json.load(f)
    msg = sarif["runs"][0]["results"][0]["message"]["text"]
    rec("SARIF message == description (not title-only)", msg == DESC, msg[:60])

    # DefectDojo description + steps_to_reproduce
    with open(os.path.join(d, "findings.defectdojo.json"), encoding="utf-8") as f:
        dd = json.load(f)
    rec("DefectDojo description == description", dd["findings"][0]["description"] == DESC)
    rec("DefectDojo steps_to_reproduce populated",
        "GET /api/orders/123" in dd["findings"][0].get("steps_to_reproduce", ""))

    # redaction chokepoint: a credential in the findings.json BLOCKS the export
    leaky = finding(description=DESC + " Authorization: Bearer abcDEF0123456789ghiJKL leaked.")
    d2, p2 = write_findings(leaky)
    r2 = run_export(p2, d2)
    rec("redaction: credential in findings.json BLOCKS export",
        r2.returncode == 4 and "BLOCKED" in r2.stdout, f"rc={r2.returncode}")

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
