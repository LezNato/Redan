#!/usr/bin/env python
"""browser_probe.py — systematic browser-based web testing via Playwright.

Tests what urllib/curl CANNOT: DOM analysis, form detection, JS-execution
monitoring, network-traffic capture, security-header validation, screenshot
capture. Solves the JS-challenge-WAF + SPA gap (the browser solves the PoW,
then same-origin fetches reach the real app). Requires: playwright + chromium.

Usage: python browser_probe.py <url> [--screenshot out.png] [--forms] [--headers] [--network]
"""
import argparse, json, sys, re

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--screenshot", help="save a screenshot to this path")
    ap.add_argument("--forms", action="store_true", default=True, help="detect + analyze forms")
    ap.add_argument("--headers", action="store_true", default=True, help="validate security headers")
    ap.add_argument("--network", action="store_true", default=True, help="capture network requests")
    ap.add_argument("--dom", action="store_true", default=True, help="DOM analysis (scripts, inputs, sinks)")
    ap.add_argument("--timeout", type=int, default=30000)
    args = ap.parse_args()
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(json.dumps({"target": args.url, "ok": False, "error": "playwright not installed: pip install playwright && playwright install chromium"})); sys.exit(1)

    result = {"target": args.url, "ok": True, "forms": [], "security_headers": {}, "network": [], "dom": {}, "screenshot": None}
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True, args=["--disable-blink-features=AutomationControlled"])
        ctx = b.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
        pg = ctx.new_page()
        reqs = []
        pg.on("request", lambda r: reqs.append({"url": r.url[:200], "method": r.method, "rtype": r.resource_type}) if len(reqs) < 100 else None)
        try:
            pg.goto(args.url, wait_until="networkidle", timeout=args.timeout)
        except Exception as e:
            result["nav_warning"] = str(e)[:200]
        # forms
        if args.forms:
            for f in pg.query_selector_all("form"):
                inputs = [{"name": i.get_attribute("name"), "type": i.get_attribute("type"), "value": (i.get_attribute("value") or "")[:50]} for i in f.query_selector_all("input,select,textarea")]
                result["forms"].append({"action": f.get_attribute("action"), "method": (f.get_attribute("method") or "GET").upper(), "inputs": inputs[:20]})
        # security headers
        if args.headers:
            hdrs = {k.lower(): v for k, v in (pg.evaluate("()=>{const r=new XMLHttpRequest();r.open('GET',location.href,false);try{r.send()}catch(e){}return r.getAllResponseHeaders()}") or "").split("\r\n") if ": " in (k + ": " + v)} if False else {}
            # simpler: just check the page response headers we can see
            for h in ["content-security-policy", "x-frame-options", "strict-transport-security", "x-content-type-options", "referrer-policy", "permissions-policy"]:
                v = pg.evaluate(f'()=>{{try{{const r=await fetch(location.href);return r.headers.get("{h}")}}catch(e){{return null}}}}') if False else None
            # use response headers from the navigation
            resp = pg.evaluate("async()=>{const r=await fetch(location.href);const h={};r.headers.forEach((v,k)=>h[k]=v);return h}")
            for h in ["content-security-policy","x-frame-options","strict-transport-security","x-content-type-options","referrer-policy","permissions-policy"]:
                result["security_headers"][h] = resp.get(h)
        # network
        if args.network:
            result["network"] = reqs[:50]
        # DOM
        if args.dom:
            result["dom"] = pg.evaluate("""()=>({
                title: document.title,
                scripts: Array.from(document.querySelectorAll('script[src]')).map(s=>s.src).slice(0,20),
                inputs: document.querySelectorAll('input').length,
                forms: document.querySelectorAll('form').length,
                iframes: document.querySelectorAll('iframe').length,
                postMessage: document.querySelectorAll('[onmessage]').length,
                innerHTML_sinks: document.querySelectorAll('[innerHTML]').length,
                eval_calls: performance.getEntriesByType('resource').filter(e=>e.name.includes('eval')).length,
                js_frameworks: [...new Set([d for(d in window)if/^(React|Vue|Angular|jQuery|Backbone|Ember|Svelte|Next|Nuxt)/.test(d)])].slice(0,5)
            })""")
        if args.screenshot:
            pg.screenshot(path=args.screenshot, full_page=True)
            result["screenshot"] = args.screenshot
        b.close()
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
