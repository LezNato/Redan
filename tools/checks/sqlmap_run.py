#!/usr/bin/env python
"""sqlmap_run.py — wrap sqlmap to CONFIRM + characterize SQL injection on a URL or
parameter and emit toolkit JSON.

By design it confirms injectability, the working technique(s), and the back-end
DBMS — it does NOT dump data (RoE: prove the vuln with the minimum, don't
exfiltrate). Data extraction is a separate, operator-gated action. The verifier
still reviews. Needs sqlmap at tools/external/sqlmap/ (bootstrap.py --sqlmap).

Usage:
  python sqlmap_run.py <url> [--data "k=v&.."] [-p param] [--level 1] [--risk 1]
                            [--technique BEU] [--threads 4] [--timeout 600]
"""
import sys, os, re, json, subprocess, shutil, argparse, tempfile

def find_sqlmap():
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, "..", "external", "sqlmap", "sqlmap.py")
    return p if os.path.exists(p) else shutil.which("sqlmap")

def run(url, data=None, param=None, level=1, risk=1, technique="BEU", threads=4, timeout=600):
    sm = find_sqlmap()
    if not sm:
        return {"ok": False, "error": "sqlmap not found — run: python tools/external/bootstrap.py --sqlmap"}
    url = url.replace("//localhost", "//127.0.0.1")
    outdir = tempfile.mkdtemp(prefix="sqlmap-")
    cmd = [sys.executable, sm, "-u", url, "--batch", "--disable-coloring", "-v", "0",
           "--level", str(level), "--risk", str(risk), "--technique", technique,
           "--threads", str(threads), "--output-dir", outdir]
    if data:  cmd += ["--data", data]
    if param: cmd += ["-p", param]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        shutil.rmtree(outdir, ignore_errors=True)
        return {"ok": False, "error": f"sqlmap timed out after {timeout}s (lower --level/--risk or scope the param)"}
    out = p.stdout + "\n" + p.stderr
    shutil.rmtree(outdir, ignore_errors=True)

    points = []
    for m in re.finditer(r"Parameter:\s*(.+?)\s*\((\w+)\)(.*?)(?=\nParameter:|\n---|\Z)", out, re.S):
        name, place, block = m.group(1).strip(), m.group(2), m.group(3)
        types = [t.strip() for t in re.findall(r"Type:\s*(.+)", block)]
        titles = [t.strip() for t in re.findall(r"Title:\s*(.+)", block)]
        points.append({"parameter": name, "place": place, "types": types, "titles": titles})
    dbms = (re.search(r"back-end DBMS:\s*(.+)", out) or [None, None])
    dbms = dbms[1].strip() if dbms and dbms[1] else (re.search(r"the back-end DBMS is (.+)", out).group(1).strip()
                                                     if re.search(r"the back-end DBMS is (.+)", out) else None)
    injectable = bool(points)
    not_inj = ("do not appear to be injectable" in out) and not injectable

    findings = []
    for pp in points:
        techs = ", ".join(pp["types"]) or "SQL injection"
        sev = "critical" if any(("union" in t.lower() or "stacked" in t.lower()) for t in pp["types"]) else "high"
        findings.append({"id": "sql-injection", "severity": sev, "cwe": "CWE-89", "location": url,
                         "detail": f"{pp['place']} parameter '{pp['parameter']}' is SQL-injectable "
                                   f"({techs}); back-end DBMS: {dbms or 'unknown'}",
                         "evidence": "; ".join(pp["titles"][:3])})
    return {"target": url, "ok": True, "engine": "sqlmap", "injectable": injectable,
            "not_injectable": not_inj, "dbms": dbms, "injection_points": points, "findings": findings,
            "note": "injectability confirmed by sqlmap; data NOT dumped (RoE). Extraction is a separate gated action."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("url"); ap.add_argument("--data"); ap.add_argument("-p", "--param")
    ap.add_argument("--level", type=int, default=1); ap.add_argument("--risk", type=int, default=1)
    ap.add_argument("--technique", default="BEU"); ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=600)
    a = ap.parse_args()
    print(json.dumps(run(a.url, a.data, a.param, a.level, a.risk, a.technique, a.threads, a.timeout), indent=2))
