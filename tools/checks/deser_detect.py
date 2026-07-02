#!/usr/bin/env python
"""deser_detect.py — flag insecure-deserialization SINKS (detection only).

Scans a URL's Set-Cookie values, the response body, and any value you pass for
serialized-object signatures (Java / PHP / Python-pickle / .NET ViewState / Ruby
Marshal / Node node-serialize). These are LEADS: black-box *exploitation* needs a
gadget chain (ysoserial/phpggc + the right libs present) — out of reach here and
honestly flagged as such. Detection still has real value (it points the manual
tester at the right sink).

Usage:
  python deser_detect.py <url>                 # scan cookies + body
  python deser_detect.py --value "<blob>"      # classify a single value
"""
import sys, os, re, ssl, json, base64, argparse, urllib.request, urllib.error

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

SIGNS = [
    ("java-serialized", "rO0AB"),                 # base64 of 0xAC 0xED 0x00 0x05
    ("php-serialized-object", re.compile(r'O:\d+:"[^"]+":\d+:\{')),
    ("php-serialized-array", re.compile(r'a:\d+:\{[siad]:')),
    ("dotnet-viewstate", "/wEP"),                 # common __VIEWSTATE prefix
    ("ruby-marshal", "BAh"),                       # base64 of Marshal \x04\x08
    ("node-serialize", re.compile(r'_\$\$ND_FUNC\$\$_')),
    ("python-pickle-b64", re.compile(r'^(?:gA[A-Za-z0-9+/=]{6,}|KGRw|gAN)')),
]

def classify(value):
    hits = []
    v = value.strip()
    for label, sig in SIGNS:
        if isinstance(sig, str):
            if v.startswith(sig) or sig in v:
                hits.append(label)
        elif sig.search(v):
            hits.append(label)
    # raw Java stream (not base64)
    if v[:2] == "\xac\xed" or v.startswith("\\xac\\xed"):
        hits.append("java-serialized-raw")
    return hits

def fetch(url, timeout=15):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=timeout, context=ctx)
        return r.getcode(), r.headers, r.read(200000).decode("latin-1", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.headers or {}), ""
    except Exception:
        return None, {}, ""

def scan_url(url):
    status, headers, body = fetch(url)
    findings, sinks = [], []
    cookies = headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else []
    for c in (cookies or []):
        name = c.split("=", 1)[0]
        val = c.split("=", 1)[1].split(";", 1)[0] if "=" in c else ""
        for label in classify(val):
            sinks.append({"where": f"cookie:{name}", "type": label})
    # scan body for inline serialized blobs / __VIEWSTATE
    for m in re.finditer(r'name=["\']__VIEWSTATE["\'][^>]*value=["\']([^"\']+)', body, re.I):
        for label in classify(m.group(1)) or ["dotnet-viewstate"]:
            sinks.append({"where": "body:__VIEWSTATE", "type": label})
    for label, sig in SIGNS:
        if isinstance(sig, re.Pattern) and sig.search(body):
            sinks.append({"where": "body", "type": label})
    # Java serialized blob (rO0AB = base64 of the 0xACED0005 stream header) — the low-FP, high-impact
    # string sig the loop above skips (it only scans Pattern sigs); anchored to avoid random-base64 hits.
    if re.search(r'\brO0AB[A-Za-z0-9+/]{8,}', body):
        sinks.append({"where": "body", "type": "java-serialized"})
    seen = set()
    for s in sinks:
        k = (s["where"], s["type"])
        if k in seen:
            continue
        seen.add(k)
        findings.append({"id": "deserialization-sink", "severity": "medium", "cwe": "CWE-502",
                         "detail": f"{s['type']} blob at {s['where']} — possible insecure-deserialization sink "
                                   f"(LEAD: exploitation needs a gadget chain; manual follow-up)"})
    return {"target": url, "ok": True, "status": status, "sinks": [{"where": w, "type": t} for (w, t) in seen], "findings": findings,
            "note": "detection only — deserialization RCE needs framework-specific gadgets (ysoserial/phpggc)"}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?"); ap.add_argument("--value")
    a = ap.parse_args()
    if a.value:
        print(json.dumps({"value_classified": classify(a.value)}, indent=2))
    elif a.url:
        print(json.dumps(scan_url(a.url), indent=2))
    else:
        print("usage: deser_detect.py <url> | --value <blob>"); sys.exit(2)
