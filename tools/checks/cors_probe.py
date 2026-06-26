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
import sys, json, ssl, argparse, urllib.request, urllib.error

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE

def _req(url, origin):
    try:
        r = urllib.request.urlopen(urllib.request.Request(
            url, headers={"User-Agent": UA, "Origin": origin, "Accept": "application/json,text/html;q=0.9"}),
            timeout=15, context=_CTX)
        return r.status, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}
    except Exception:
        return None, {}

def check(url):
    findings = []
    for origin in ("https://evil-cors-probe.test", "null"):
        s, h = _req(url, origin)
        if s is None:
            continue
        acao = h.get("access-control-allow-origin") or ""
        acac = (h.get("access-control-allow-credentials") or "").lower()
        reflected = (acao == origin) or (origin == "null" and acao.lower() == "null") or acao == "*"
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
