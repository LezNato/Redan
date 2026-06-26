#!/usr/bin/env python
"""http_headers.py — deterministic HTTP security-header / cookie / disclosure check.

Fetches a URL (non-destructive GET, follows redirects, ignores cert validity like
curl -k) and reports which security headers are present/missing, cookie flags, and
version-disclosure headers. Emits JSON to stdout — agents fold it into findings;
the verifier trusts the JSON over an LLM's recollection.

Usage: python http_headers.py <url> [<url> ...]
"""
import sys, json, ssl, re, urllib.request, urllib.error, argparse

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
SEC_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options",
               "x-content-type-options", "referrer-policy", "permissions-policy"]
DISCLOSURE = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

def fetch(url, timeout=20):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return r.getcode(), r.headers, r.geturl(), None
    except urllib.error.HTTPError as e:
        return e.code, e.headers, url, None
    except Exception as e:
        return None, None, url, str(e)

def check(url):
    code, headers, final, err = fetch(url)
    if err or headers is None:
        return {"target": url, "ok": False, "error": err or "no response"}
    hl = {k.lower(): v for k, v in headers.items()}
    present = {h: hl[h] for h in SEC_HEADERS if h in hl}
    missing = [h for h in SEC_HEADERS if h not in hl]
    cookies = []
    for c in headers.get_all("Set-Cookie", []):
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        ss = re.search(r"samesite=(\w+)", low)
        cookies.append({"name": name, "secure": "secure" in low,
                        "httponly": "httponly" in low, "samesite": ss.group(1) if ss else None})
    disclosure = {h: hl[h] for h in DISCLOSURE if h in hl}
    return {
        "target": url, "ok": True, "status": code, "final_url": final,
        "security_headers": {"present": present, "missing": missing},
        "cookies": cookies, "disclosure": disclosure,
        "findings": (
            ([{"id": "missing-security-headers", "severity": "low",
               "detail": "Missing: " + ", ".join(missing)}] if missing else [])
            + ([{"id": "version-disclosure", "severity": "info",
                 "detail": "; ".join(f"{k}: {v}" for k, v in disclosure.items())}] if disclosure else [])
            + [{"id": "insecure-cookie", "severity": "low",
                "detail": f"cookie {c['name']} missing " + ", ".join(
                    f for f, ok in [("Secure", c["secure"]), ("HttpOnly", c["httponly"]),
                                    ("SameSite", c["samesite"])] if not ok)}
               for c in cookies if not (c["secure"] and c["httponly"] and c["samesite"])]
        ),
    }

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Deterministic HTTP security-header / cookie / disclosure check.")
    ap.add_argument("urls", nargs="+", metavar="url", help="one or more target URLs")
    args = ap.parse_args()
    out = [check(u) for u in args.urls]
    print(json.dumps(out if len(out) > 1 else out[0], indent=2))
