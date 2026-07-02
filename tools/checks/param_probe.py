#!/usr/bin/env python
"""param_probe.py — HTTP parameter discovery (Arjun-style).

Discovers hidden HTTP parameters by sending common param names + comparing
the response (length/status/reflection) to a baseline. Finds params that
endpoints accept but aren't visible in the page source — a lead source for
injection/access-control testing.

Usage: python param_probe.py <url> [--method GET|POST] [--wordlist params.txt]
       [--concurrency 8] [--diff-threshold 50]
"""
import argparse, json, sys, urllib.request, urllib.parse, urllib.error, ssl, concurrent.futures, hashlib

COMMON_PARAMS = [
    "id","user","username","name","email","password","pass","token","key","api","q","query",
    "search","cmd","command","exec","file","path","url","redirect","return","next","page",
    "action","type","mode","debug","test","admin","role","access","auth","session","csrf",
    "callback","json","xml","data","input","value","msg","message","text","content","body",
    "src","source","dest","target","host","port","ip","addr","db","sql","query_id","item",
    "order","sort","filter","limit","offset","count","size","format","lang","locale","theme",
    "template","view","layout","render","output","export","download","upload","attach","image",
    "img","media","video","doc","document","report","log","debug","trace","profile","account",
    "settings","config","pref","option","flag","enable","disable","status","state","active",
    "verified","approved","paid","price","amount","qty","quantity","total","subtotal","discount",
    "coupon","promo","vat","tax","currency","country","city","zip","phone","fax","mobile",
    "address","street","state","company","org","org_id","tenant","workspace","team","group",
    "project","repository","branch","commit","sha","tag","release","version","build","env",
    "secret","private","public","cert","ssl","tls","dns","mx","txt","srv","cname","soa",
]

def probe(url, param, method, baseline_len, baseline_status, ctx, threshold):
    sep = "&" if "?" in url else "?"
    marker = f"redan_{hashlib.md5(param.encode()).hexdigest()[:6]}"   # a payload-unique sentinel VALUE
    test_url = f"{url}{sep}{param}={marker}"
    try:
        if method == "POST":
            marker = f"redan_{param}"
            data = urllib.parse.urlencode({param: marker}).encode()
            req = urllib.request.Request(url, data=data, method="POST")
        else:
            req = urllib.request.Request(test_url)
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; ParamProbe/1.0)")
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            body = r.read(50000)
            status, length = r.status, len(body)
            reflected = marker.encode() in body   # the injected VALUE reflecting, not the param NAME (often a common word)
            if abs(length - baseline_len) > threshold or status != baseline_status or reflected:
                return {"param": param, "status": status, "length_delta": length - baseline_len, "reflected": reflected, "interesting": True}
    except urllib.error.HTTPError as e:
        if e.code != baseline_status:
            return {"param": param, "status": e.code, "length_delta": 0, "reflected": False, "interesting": True}
    except Exception:
        pass
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--method", choices=["GET","POST"], default="GET")
    ap.add_argument("--wordlist", help="custom param wordlist (one per line)")
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--diff-threshold", type=int, default=50, help="response length delta to flag as interesting")
    args = ap.parse_args()
    params = COMMON_PARAMS
    if args.wordlist:
        with open(args.wordlist) as f:
            params = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    ctx = ssl.create_default_context(); ctx.check_certy = False if False else ctx.check_hostname
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    # baseline
    try:
        req = urllib.request.Request(args.url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            baseline_len, baseline_status = len(r.read(50000)), r.status
    except Exception as e:
        print(json.dumps({"target": args.url, "ok": False, "error": str(e)[:200]})); sys.exit(1)
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(probe, args.url, p, args.method, baseline_len, baseline_status, ctx, args.diff_threshold): p for p in params}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r: found.append(r)
    found.sort(key=lambda x: abs(x.get("length_delta",0)), reverse=True)
    print(json.dumps({"target": args.url, "ok": True, "method": args.method, "params_tested": len(params), "params_found": len(found), "found": found, "note": "each found param is a lead — test for injection/access-control/reflection"}, indent=2))

if __name__ == "__main__":
    main()
