#!/usr/bin/env python
"""sri_check.py — third-party-JS supply-chain / Subresource-Integrity check (stdlib only).

Enumerates cross-origin <script src> on a page, checks each for integrity=/crossorigin=
attributes, fetches each script body, and flags cookie-access / exfil-sink patterns. Emits a
finding when a cross-origin script LACKS integrity AND the page has no CSP (the supply-chain /
cookie-theft exposure). Source of a real third-party-JS supply-chain finding.

Usage: python sri_check.py <url> [--html <captured.html>]
  (--html: parse a pre-captured HTML file instead of fetching — needed when a JS-challenge
   WAF makes urllib blind to the real page; pair with http_headers.py to confirm CSP absence)
"""
import os, sys, json, re, argparse, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _http import get as http_get
SINK_RE = re.compile(r"document\.cookie|localStorage|sessionStorage|\.fetch\(|XMLHttpRequest|sendBeacon|postMessage|\beval\(|innerHTML", re.I)
SCRIPT_RE = re.compile(r'<script[^>]*\bsrc=["\']([^"\']+)["\'][^>]*>', re.I)
INTEGRITY_RE = re.compile(r'\bintegrity=["\']', re.I)
CSP_META_RE = re.compile(r'<meta[^>]+http-equiv=["\']?Content-Security-Policy["\']?', re.I)

def fetch(url, timeout=15):
    r = http_get(url, timeout=timeout, max_body=5_000_000)
    return "" if (r.error or r.status >= 400) else r.text

def check(url, html_override=None):
    html = html_override if html_override is not None else fetch(url)
    if not html:
        return {"target": url, "ok": False, "error": "fetch failed (WAF/challenge? use --html <file>)", "findings": []}
    page_host = urllib.parse.urlparse(url).netloc
    scripts = []
    for m in SCRIPT_RE.finditer(html):
        tag = m.group(0); src = m.group(1)
        full = urllib.parse.urljoin(url, src)
        if not urllib.parse.urlparse(full).netloc:
            continue
        scripts.append({"src": full,
                        "cross_origin": urllib.parse.urlparse(full).netloc != page_host,
                        "has_integrity": bool(INTEGRITY_RE.search(tag))})
    for s in scripts:
        if s["cross_origin"]:
            body = fetch(s["src"])
            sinks = sorted(set(SINK_RE.findall(body[:8000])))
            s["reads_cookie"] = "document.cookie" in " ".join(sinks)
            s["exfil_sinks"] = sinks[:8]
    missing = [s for s in scripts if s["cross_origin"] and not s["has_integrity"]]
    cookie_scripts = [s["src"] for s in missing if s.get("reads_cookie")]
    has_csp_meta = bool(CSP_META_RE.search(html))
    findings = []
    if missing:
        findings.append({"id": "missing-sri-third-party-scripts", "severity": "low",
                         "detail": f"{len(missing)} cross-origin script(s) loaded WITHOUT Subresource Integrity — a supply-chain / cookie-theft exposure (a compromised CDN -> arbitrary JS in the page's origin). Impact is uncontained only if CSP is also absent; header CSP is invisible from an HTML fetch, so confirm via http_headers.py.",
                         "scripts": [s["src"] for s in missing], "cookie_reading": cookie_scripts,
                         "csp_meta_present": has_csp_meta,
                         "note": "header CSP not visible from an HTML fetch — confirm via http_headers.py; no-CSP + missing-SRI + a cookie-reading script is the F-10 condition"})
    return {"target": url, "ok": True,
            "cross_origin_scripts": [s for s in scripts if s["cross_origin"]],
            "missing_integrity": [s["src"] for s in missing],
            "cookie_access": cookie_scripts, "findings": findings}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Third-party-JS SRI / supply-chain check")
    ap.add_argument("url"); ap.add_argument("--html", help="pre-captured HTML file to parse (WAF-safe)")
    a = ap.parse_args()
    html_override = None
    if a.html:
        try:
            html_override = open(a.html, encoding="utf-8").read()
        except Exception as e:
            print(f"--html read error: {e}"); sys.exit(2)
    print(json.dumps(check(a.url, html_override), indent=2))
