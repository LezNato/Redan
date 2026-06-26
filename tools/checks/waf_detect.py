#!/usr/bin/env python
"""waf_detect.py — fingerprint the edge protection BEFORE scanning, and route testing.

A JS proof-of-work challenge (Imunify360 "One moment, please...", Cloudflare
"Checking your browser", etc.) returns a uniform ~challenge page to non-JS clients
— so urllib/curl-based tools (path_probe, fuzzer, js_secrets, nuclei) can't pass it
and will emit FALSE POSITIVES against the challenge shell. Run this first: it tells
you whether the deterministic tools will work, or whether you must route active
testing through the BROWSER agents (web-tester/verifier), which solve the challenge
like a real attacker's headless browser.

Probes the target as (1) a browser navigation and (2) an XHR/fetch, plus a
nonexistent path, and classifies the posture. Usage:  python waf_detect.py <url>
"""
import sys, re, ssl, json, argparse, urllib.request, urllib.error

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
NAV = {"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
       "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1",
       "Upgrade-Insecure-Requests": "1"}
XHR = {"User-Agent": UA, "Accept": "*/*", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "X-Requested-With": "XMLHttpRequest"}
CHALLENGE = ["one moment, please", "checking your browser", "just a moment", "enable javascript",
             "ddos protection by", "attention required", "imunify360", "please wait while we verify",
             "verifying you are human", "ray id"]
WAF_HINTS = {"openresty": "openresty", "litespeed": "litespeed", "cloudflare": "cloudflare",
             "sucuri": "sucuri", "wordfence": "wordfence", "imunify": "imunify"}

def get(url, headers, timeout=15):
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout,
                                   context=ssl._create_unverified_context())
        b = r.read(40000); return r.getcode(), dict(r.headers), b.decode("latin-1", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read(8000).decode("latin-1", "replace") if hasattr(e, "read") else "")
    except Exception as e:
        return None, {}, str(e)

def looks_challenge(body):
    low = (body or "").lower()
    return next((s for s in CHALLENGE if s in low), None)

def detect(url):
    url = url.rstrip("/")
    nav_s, nav_h, nav_b = get(url + "/", NAV)
    xhr_s, xhr_h, xhr_b = get(url + "/", XHR)
    miss_s, _, miss_b = get(url + "/pt-waf-nonexistent-9f3a2c.html", NAV)
    server = (nav_h.get("Server") or xhr_h.get("Server") or "").lower()
    waf = next((name for name, hint in WAF_HINTS.items() if hint in server), None)
    challenge_sig = looks_challenge(nav_b) or looks_challenge(xhr_b)
    # uniform-page heuristic: nav, xhr and the missing path all ~same length => catch-all challenge/block
    lens = [len(b or "") for b in (nav_b, xhr_b, miss_b)]
    uniform = max(lens) - min(lens) <= max(40, int(min(lens) * 0.05)) if min(lens) else False
    xhr_blocked = xhr_s in (403, 406, 415)
    js_challenge = bool(challenge_sig) or (uniform and nav_s == 200 and miss_s == 200)

    if js_challenge:
        posture = "js-challenge"
        channel = "BROWSER REQUIRED — route active testing via the browser agents (web-tester/verifier); urllib/curl tools will be blocked and emit false positives"
    elif xhr_blocked and nav_s and nav_s < 400:
        posture = "xhr-blocked-waf"
        channel = "deterministic tools work for navigations; XHR/fetch-style probes are blocked (415/403) — prefer navigation-style requests"
    elif waf and nav_s and nav_s < 400:
        posture = "waf-present-passive"
        channel = "WAF present but not actively challenging — deterministic tools should work; watch for rate-limit re-challenge"
    else:
        posture = "clean-or-passive"
        channel = "no JS challenge detected — deterministic tools should reach the app directly"

    findings = []
    if js_challenge:
        findings.append({"id": "edge-js-challenge", "severity": "info",
                         "detail": f"JS proof-of-work challenge at the edge ({waf or 'unknown WAF'}"
                                   + (f", sig '{challenge_sig}'" if challenge_sig else "")
                                   + ") — a browser passes it, urllib/curl do not. Route via browser agent."})
    return {"target": url, "ok": True, "waf": waf, "server": server or None, "posture": posture,
            "nav_status": nav_s, "xhr_status": xhr_s, "missing_status": miss_s,
            "challenge_signature": challenge_sig, "uniform_shell": uniform, "xhr_blocked": xhr_blocked,
            "recommended_channel": channel, "findings": findings}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("url")
    print(json.dumps(detect(ap.parse_args().url), indent=2))
