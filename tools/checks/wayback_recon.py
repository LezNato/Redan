#!/usr/bin/env python
"""wayback_recon.py — historical-surface recon via the Wayback Machine CDX API (stdlib, no key).

Mines archived URLs (web.archive.org/cdx) for a host. Sees what USED to exist — current-only
tools (wp_fingerprint / path_probe / crawler) cannot. Finds: old plugin/theme versions (feed to
cve_lookup), deprecated/removed endpoints (still reachable = a finding class), leaked secrets in
since-deleted pages, forgotten admin paths. Hits archive.org, NOT the target (passive).

Usage: python wayback_recon.py <host-or-url> [--from YYYY] [--to YYYY] [--limit 1000]
"""
import sys, json, re, argparse, urllib.request, urllib.parse

CDX = "https://web.archive.org/cdx/search/cdx"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

INTERESTING = re.compile(
    r"wp-content/plugins|wp-content/themes|wp-admin|wp-json|wp-includes|/api/|/feed|/embed|"
    r"backup|\.sql|\.zip|\.env|\.bak|\.git|/uploads|/inc/|/lib/|xmlrpc|readme|license|sitemap|"
    r"config|secret|token|apikey|api_key", re.I)
OLD_VERSION = re.compile(r"/wp-content/(?:plugins|themes)/([^/]+)/[^?]*?(\d+\.\d+(?:\.\d+)?)", re.I)

def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception:
        return ""

def sweep(target, frm=None, to=None, limit=1000, timeout=30):
    host = urllib.parse.urlparse(target).netloc or target.split("/")[0]
    q = {"url": host + "/*", "output": "json", "fl": "original,timestamp,statuscode",
         "collapse": "urlkey", "limit": str(limit)}
    if frm: q["from"] = frm
    if to: q["to"] = to
    raw = fetch(CDX + "?" + urllib.parse.urlencode(q), timeout)
    rows = []
    try:
        j = json.loads(raw)
        rows = j[1:] if j else []
    except Exception:
        pass
    paths = sorted({row[0].split(host, 1)[-1] for row in rows if len(row) > 0 and host in row[0]})
    interesting = [p for p in paths if INTERESTING.search(p)]
    old_versions = {}
    for row in rows:
        if not row: continue
        m = OLD_VERSION.search(row[0])
        if m:
            old_versions.setdefault(m.group(1), set()).add(m.group(2))
    old_versions = {k: sorted(v) for k, v in old_versions.items()}
    findings = []
    if interesting:
        findings.append({"id": "archived-interesting-paths", "severity": "info",
                         "detail": f"{len(interesting)} archived paths match sensitive/deprecated/old-version patterns — re-test LIVE; a removed-but-still-reachable endpoint is a finding class",
                         "sample": interesting[:40]})
    if old_versions:
        findings.append({"id": "archived-old-versions", "severity": "info",
                         "detail": "historical plugin/theme versions captured — feed each to cve_lookup for old-version CVEs (a version the site has SINCE upgraded past may still inform the threat model)",
                         "versions": old_versions})
    return {"target": host, "ok": True, "archived_url_count": len(rows),
            "paths_count": len(paths), "deprecated_or_interesting": interesting[:60],
            "old_versions": old_versions, "findings": findings,
            "note": "PASSIVE (queries archive.org, not the target). Archived artifacts are LEADS — re-test live before reporting (pitfalls.md)."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Wayback Machine CDX historical-surface recon")
    ap.add_argument("url")
    ap.add_argument("--from", dest="frm"); ap.add_argument("--to"); ap.add_argument("--limit", type=int, default=1000)
    a = ap.parse_args()
    print(json.dumps(sweep(a.url, a.frm, a.to, a.limit), indent=2))
