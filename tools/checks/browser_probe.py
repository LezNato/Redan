#!/usr/bin/env python
"""browser_probe.py — systematic browser-based web testing via Playwright.

Tests what urllib/curl CANNOT: DOM analysis, form detection, network-traffic
capture, security-header validation, screenshot capture. Solves the JS-challenge-WAF
+ SPA gap (the browser solves the PoW, then same-origin fetches reach the real app).

`--proxy` routes Chromium through a proxy sourced by `proxy_rotate.py` — the channel
that beats BOTH a per-IP graylist (proxy restores TCP reach) AND a JS proof-of-work
(the browser solves it). When the edge serves a challenge interstitial ("One moment,
please..."), this tool waits for it to clear before reading the real page.

`--proxy` accepts a COMMA-SEPARATED LIST and FAILS OVER: free proxies are ephemeral
and a proxy that merely reaches the edge (proxy_rotate "hit", challenge:true) may
still fail to solve the PoW in a browser. Pass several (e.g. the top hits from
proxy_rotate) and the tool tries each until one actually clears the challenge — the
robustness gap that left a single-proxy run stuck on the interstitial. Requires:
playwright + chromium.

Usage: python browser_probe.py <url> [--proxy http://ip:port[,ip2:port2,...]] [--screenshot out.png]
        [--no-forms|--no-headers|--no-network|--no-dom] [--timeout 30000]
"""
import argparse, json, re, sys

CHALLENGE = "moment|checking your browser|just a moment"
_CHALL_RE = re.compile(CHALLENGE, re.I)


def _probe(p, url, proxy, args):
    """One attempt through `proxy` (or direct if None). Returns the result dict; on a
    challenge that did NOT clear it returns EARLY (skips extraction) so the caller can
    fail over to the next proxy cheaply."""
    result = {"target": url, "ok": True, "proxy": proxy, "forms": [], "security_headers": {},
              "network": [], "dom": {}, "screenshot": None}
    launch_kw = {"headless": True, "args": ["--disable-blink-features=AutomationControlled"]}
    if proxy:
        launch_kw["proxy"] = {"server": proxy}
    b = p.chromium.launch(**launch_kw)
    ctx = b.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
    pg = ctx.new_page()
    reqs = []
    pg.on("request", lambda r: reqs.append({"url": r.url[:200], "method": r.method, "rtype": r.resource_type}) if len(reqs) < 100 else None)
    try:
        pg.goto(url, wait_until="domcontentloaded", timeout=args.timeout)
    except Exception as e:
        result["nav_warning"] = str(e)[:200]
    # if the edge served a JS proof-of-work, wait for it to clear before reading the page
    blocked = False
    try:
        if _CHALL_RE.search(pg.title() or ""):
            pg.wait_for_function("() => !/moment|checking your browser|just a moment/i.test(document.title || '')", timeout=args.timeout)
            result["challenge_solved"] = True
    except Exception as e:
        result["challenge_solved"] = False
        result["challenge_wait_error"] = str(e)[:150]
        blocked = True
    result["final_title"] = (pg.title() or "")[:120]
    result["final_url"] = pg.url
    if _CHALL_RE.search(result["final_title"] or ""):
        blocked = True
    if blocked:
        b.close()
        return result  # challenge not cleared — caller may try the next proxy
    if args.forms:
        try:
            for f in pg.query_selector_all("form"):
                inputs = [{"name": i.get_attribute("name"), "type": i.get_attribute("type"), "value": (i.get_attribute("value") or "")[:50]} for i in f.query_selector_all("input,select,textarea")]
                result["forms"].append({"action": f.get_attribute("action"), "method": (f.get_attribute("method") or "GET").upper(), "inputs": inputs[:20]})
        except Exception as e:
            result["forms_error"] = str(e)[:150]
    # security headers via same-origin fetch (carries the edge-clearance cookie post-challenge)
    if args.headers:
        try:
            resp = pg.evaluate("async()=>{try{const r=await fetch(location.href);const h={};r.headers.forEach((v,k)=>h[k]=v);return h}catch(e){return {}}}")
            for h in ["content-security-policy", "x-frame-options", "strict-transport-security", "x-content-type-options", "referrer-policy", "permissions-policy"]:
                result["security_headers"][h] = resp.get(h)
            result["server"] = resp.get("server")
        except Exception as e:
            result["headers_error"] = str(e)[:150]
    if args.network:
        result["network"] = reqs[:50]
    if args.dom:
        try:
            result["dom"] = pg.evaluate("""()=>({
                title: document.title,
                scripts: Array.from(document.querySelectorAll('script[src]')).map(s=>s.src).slice(0,20),
                inputs: document.querySelectorAll('input').length,
                forms: document.querySelectorAll('form').length,
                iframes: document.querySelectorAll('iframe').length,
                wp_content: !!document.querySelector('link[href*="wp-content"],script[src*="wp-content"]'),
                js_frameworks: [...new Set(Object.keys(window).filter(d=>/^(React|Vue|Angular|jQuery|Backbone|Ember|Svelte|Next|Nuxt)/.test(d)))].slice(0,5)
            })""")
        except Exception as e:
            result["dom_error"] = str(e)[:150]
    if args.screenshot:
        pg.screenshot(path=args.screenshot, full_page=True)
        result["screenshot"] = args.screenshot
    b.close()
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--proxy", help="route Chromium through this proxy (http://ip:port). Accepts a COMMA-SEPARATED LIST and fails over to the next when one cannot clear the PoW — pair with proxy_rotate.py for graylisted/JS-challenge edges")
    ap.add_argument("--screenshot", help="save a full-page screenshot to this path")
    ap.add_argument("--forms", dest="forms", action="store_true", default=True)
    ap.add_argument("--no-forms", dest="forms", action="store_false")
    ap.add_argument("--headers", dest="headers", action="store_true", default=True)
    ap.add_argument("--no-headers", dest="headers", action="store_false")
    ap.add_argument("--network", dest="network", action="store_true", default=True)
    ap.add_argument("--no-network", dest="network", action="store_false")
    ap.add_argument("--dom", dest="dom", action="store_true", default=True)
    ap.add_argument("--no-dom", dest="dom", action="store_false")
    ap.add_argument("--timeout", type=int, default=30000)
    args = ap.parse_args()
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(json.dumps({"target": args.url, "ok": False, "error": "playwright not installed: pip install playwright && playwright install chromium"})); sys.exit(1)

    proxies = [x.strip() for x in args.proxy.split(",") if x.strip()] if args.proxy else [None]
    with sync_playwright() as p:
        tried, result = [], None
        for proxy in proxies:
            result = _probe(p, args.url, proxy, args)
            tried.append(proxy)
            blocked = result.get("challenge_solved") is False or bool(_CHALL_RE.search(result.get("final_title", "") or ""))
            if not blocked:
                break  # this proxy cleared the challenge (or there was none) — use it
        if len(proxies) > 1:
            result["proxies_tried"] = tried
            result["proxy_failover"] = len(tried) > 1
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
