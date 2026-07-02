#!/usr/bin/env python
"""cors_probe.py — CORS misconfiguration probe (reflected origin + credentials).

Tests whether an endpoint reflects an arbitrary Origin in Access-Control-Allow-Origin AND
sends Access-Control-Allow-Credentials: true — the dangerous combo (a cross-origin attacker
page can read an authenticated user's responses, CWE-942). Wildcard ACAO WITHOUT credentials
is SAFE (exposes only anonymous-readable data) and is NOT flagged as a finding. stdlib only.

A finding is emitted ONLY on reflected-arbitrary-origin + credentials (per pitfalls.md:
wildcard ACAO without credentials is the classic inflated finding). Tests an arbitrary https
origin AND a `null` origin.

Usage: python cors_probe.py <url> [<url> ...]
"""
import os, sys, json, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _http import get as http_get

def _req(url, origin):
    r = http_get(url, headers={"Origin": origin, "Accept": "application/json,text/html;q=0.9"}, timeout=15)
    return (None, {}) if r.error else (r.status, r.headers)  # r.headers is lower-cased

def check(url):
    findings = []
    for origin in ("https://evil-cors-probe.test", "null"):
        s, h = _req(url, origin)
        if s is None:
            continue
        acao = h.get("access-control-allow-origin") or ""
        acac = (h.get("access-control-allow-credentials") or "").lower()
        # NOTE: acao=="*" is deliberately NOT "reflected" — a wildcard ACAO with Allow-Credentials:true
        # is rejected by browsers (inert), so it must not fire the credentialed-read finding (pitfalls.md).
        reflected = (acao == origin) or (origin == "null" and acao.lower() == "null")
        cred = acac == "true"
        if reflected and cred:
            findings.append({"id": "cors-reflected-with-credentials", "severity": "medium",
                             "detail": f"reflects a {origin!r} origin in ACAO WITH Access-Control-Allow-Credentials: true — a cross-origin attacker page can read this authenticated user's responses (CWE-942)",
                             "origin": origin, "acao": acao, "acac": acac})
        elif reflected and not cred and acao != "*" and origin != "null":
            findings.append({"id": "cors-reflected-no-credentials", "severity": "low",
                             "detail": f"reflects a {origin!r} origin but WITHOUT credentials — exposes only anonymous-readable data (informational)"})
    # dedupe by id
    seen, dedup = set(), []
    for f in findings:
        if f["id"] not in seen:
            seen.add(f["id"]); dedup.append(f)
    return {"target": url, "ok": True, "findings": dedup,
            "note": "reflected-arbitrary-origin + Allow-Credentials:true is the dangerous combo (CWE-942). Wildcard ACAO without credentials is SAFE (pitfalls.md)."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CORS misconfiguration probe")
    ap.add_argument("urls", nargs="+")
    a = ap.parse_args()
    out = [check(u) for u in a.urls]
    print(json.dumps(out if len(out) > 1 else out[0], indent=2))
