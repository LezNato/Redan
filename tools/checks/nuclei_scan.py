#!/usr/bin/env python
"""nuclei_scan.py — wrapper around the nuclei engine (thousands of DETERMINISTIC
templates: CVEs, exposures, misconfig, default-logins, takeovers). Emits the
toolkit's JSON finding shape so finder agents fold it in and the verifier confirms.

Adds signature-based coverage that does NOT vary by model (vs LLM-guessing) and
breadth the agents don't reach — partly closing the vulnerable-component /
exposure gaps.

Needs the nuclei binary: tools/external/nuclei.exe (bootstrapped), or $NUCLEI_BIN,
or `nuclei` on PATH. ACTIVE and can be noisy — rate-limited by default; in-scope
hosts only (the calling agent enforces scope). Templates auto-update on first run.

Usage:
  python nuclei_scan.py <url> [--severity low,medium,high,critical] [--tags cve,exposure]
                              [--rate N] [--timeout SECS]
"""
import sys, os, json, subprocess, shutil, argparse

def find_nuclei():
    here = os.path.dirname(os.path.abspath(__file__))
    for c in [os.environ.get("NUCLEI_BIN"),
              os.path.join(here, "..", "external", "nuclei.exe"),
              os.path.join(here, "..", "external", "nuclei"),
              shutil.which("nuclei")]:
        if c and os.path.exists(c):
            return c
    return shutil.which("nuclei")

def scan(url, severity="medium,high,critical", tags=None, rate=50, timeout=900):
    nb = find_nuclei()
    if not nb:
        return {"ok": False, "error": "nuclei not found (tools/external/nuclei.exe, $NUCLEI_BIN, or PATH); run tools/external/bootstrap.py"}
    import urllib.parse as _up  # host-aware: rewrite ONLY when the host is exactly 'localhost' (not localhost.evil.com)
    _sp = _up.urlsplit(url)
    if _sp.hostname == "localhost":  # nuclei's resolver doesn't know 'localhost'
        url = _up.urlunsplit(_sp._replace(netloc=_sp.netloc.replace("localhost", "127.0.0.1", 1)))
    cmd = [nb, "-target", url, "-jsonl", "-silent", "-no-color", "-disable-update-check",
           "-severity", severity, "-rate-limit", str(rate)]
    if tags:
        cmd += ["-tags", tags]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"nuclei timed out after {timeout}s — narrow with --tags/--severity"}
    findings = []
    for line in p.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        info = r.get("info", {}) or {}
        cls = info.get("classification") or {}
        def join(v): return ",".join(v) if isinstance(v, list) else v
        findings.append({
            "id": r.get("template-id"),
            "title": info.get("name"),
            "severity": (info.get("severity") or "info").lower(),
            "location": r.get("matched-at") or r.get("host"),
            "cwe": join(cls.get("cwe-id")),
            "cve": join(cls.get("cve-id")),
            "tags": info.get("tags"),
            "detail": info.get("description"),
        })
    return {"target": url, "ok": True, "engine": "nuclei", "count": len(findings),
            "findings": findings,
            "note": "deterministic template matches; the verifier still confirms each "
                    "(a version->CVE template hit is a LEAD until exploitability is shown — pitfalls.md)"}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--severity", default="medium,high,critical")
    ap.add_argument("--tags", default=None)
    ap.add_argument("--rate", type=int, default=50, help="requests/sec (lower for prod targets)")
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()
    print(json.dumps(scan(a.url, a.severity, a.tags, a.rate, a.timeout), indent=2))
