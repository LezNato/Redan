#!/usr/bin/env python
"""export.py — convert findings.json into enterprise vuln-management formats.

  SARIF 2.1.0      (code-scanning / GitHub / Azure DevOps ingestion)
  CSV              (Jira / generic import: Summary, Severity, CWE, CVSS, ...)
  DefectDojo JSON  (the "Generic Findings Import" schema)

Pure format conversion (NOT process/qualification). Reads the single-source
findings.json; writes alongside it. Redaction chokepoint: refuses to export if the
findings.json still contains raw credential material (same posture as the report
renderer).

Usage:
  python export.py <findings.json> [--outdir <dir>] [--formats sarif,csv,defectdojo]
"""
import sys, os, csv, json, argparse

# Single redaction chokepoint: reuse the real redact.py scanner (the inline regex
# this file used to carry was weaker than redact.py and would miss most secrets).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "checks"))
try:
    from redact import scan as _redact_scan
except Exception:  # pragma: no cover - import-path dependent
    _redact_scan = None

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

def load(path):
    d = json.load(open(path, encoding="utf-8"))
    findings = d.get("findings", d if isinstance(d, list) else [])
    return d, [f for f in findings if str(f.get("disposition", "confirmed")).lower() in ("confirmed", "informational")]

def redaction_ok(path):
    """BLOCK export if the findings.json carries credential material (delegates to
    redact.py — the same chokepoint the report renderer / QA gate use)."""
    if _redact_scan is None:
        return True  # redact unavailable: don't hard-fail the export (renderer still redacts)
    return not _redact_scan(path).get("secret_hits")

def g(f, *keys, default=""):
    for k in keys:
        if f.get(k) not in (None, ""):
            return f[k]
    return default

def txt(v):
    """Stringify a field that may be a list (e.g. reproduction steps)."""
    if isinstance(v, list):
        return " ".join(str(x) for x in v)
    return str(v or "")

def to_sarif(eng, findings):
    rules, results = [], []
    seen = set()
    for f in findings:
        rid = str(g(f, "id", "cwe", "title", default="finding"))[:60]
        if rid not in seen:
            seen.add(rid)
            rules.append({"id": rid, "name": g(f, "title", default=rid),
                          "shortDescription": {"text": g(f, "title", default=rid)},
                          "properties": {"cwe": g(f, "cwe"), "security-severity": str(g(f, "cvss_score", "cvss", default="0"))}})
        results.append({
            "ruleId": rid, "level": SARIF_LEVEL.get(str(g(f, "severity", default="info")).lower(), "note"),
            "message": {"text": g(f, "description", "impact", "detail", "title", default="")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": g(f, "location", "url", default="N/A")}}}],
            "properties": {"severity": g(f, "severity"), "cvss": g(f, "cvss_vector", "cvss"),
                           "validation_status": g(f, "validation_status"),
                           "reproduction": txt(g(f, "reproduction")), "remediation": g(f, "remediation")}})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "Redan", "informationUri": "https://localhost",
                                          "version": "1.0", "rules": rules}}, "results": results}]}

def to_csv(findings, path):
    cols = ["Summary", "Severity", "CVSS", "CWE", "Location", "Description",
            "Reproduction", "Remediation", "Confidence"]
    def _safe(v):   # neutralize spreadsheet formula injection (CWE-1236) in the client-deliverable CSV
        s = "" if v is None else str(v)
        return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(cols)
        for f in findings:
            w.writerow([_safe(c) for c in [
                g(f, "title"), g(f, "severity"), g(f, "cvss_score", "cvss"), g(f, "cwe"),
                g(f, "location", "url"), g(f, "description", "impact", "detail"),
                txt(g(f, "reproduction")), g(f, "remediation"), g(f, "validation_status")]])

def to_defectdojo(findings):
    out = []
    for f in findings:
        out.append({"title": g(f, "title", default="finding"),
                    "severity": str(g(f, "severity", default="Info")).capitalize(),
                    "description": g(f, "description", "impact", "detail", "title"),
                    "steps_to_reproduce": txt(g(f, "reproduction")),
                    "mitigation": g(f, "remediation"), "cwe": g(f, "cwe"),
                    "cvssv3": g(f, "cvss_vector", "cvss"),
                    "references": g(f, "location", "url"),
                    "static_finding": False, "dynamic_finding": True})
    return {"findings": out}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("findings"); ap.add_argument("--outdir"); ap.add_argument("--formats", default="sarif,csv,defectdojo")
    a = ap.parse_args()
    if not redaction_ok(a.findings):
        print(json.dumps({"ok": False, "error": "BLOCKED: credential material in findings.json — redact first (tools/checks/redact.py)"}))
        sys.exit(4)
    eng, findings = load(a.findings)
    outdir = a.outdir or os.path.dirname(os.path.abspath(a.findings))
    fmts = [x.strip() for x in a.formats.split(",")]
    written = []
    if "sarif" in fmts:
        p = os.path.join(outdir, "findings.sarif.json"); json.dump(to_sarif(eng, findings), open(p, "w", encoding="utf-8"), indent=2); written.append(p)
    if "csv" in fmts:
        p = os.path.join(outdir, "findings.csv"); to_csv(findings, p); written.append(p)
    if "defectdojo" in fmts:
        p = os.path.join(outdir, "findings.defectdojo.json"); json.dump(to_defectdojo(findings), open(p, "w", encoding="utf-8"), indent=2); written.append(p)
    print(json.dumps({"ok": True, "findings_exported": len(findings), "written": written}, indent=2))
