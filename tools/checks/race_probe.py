#!/usr/bin/env python
"""race_probe.py — single-endpoint concurrency / TOCTOU race detector (stdlib only).

A real attacker wins race conditions by hitting a check-then-act endpoint N times in the SAME
millisecond (coupon/voucher burn, balance double-spend, quota bypass, role self-grant). This tool
fires K copies CONCURRENTLY (barrier release) FIRST (on fresh state), reads the effected-count
metric, then runs a serial-K for context. If the concurrent burst produced MORE effects than a
healthy endpoint should (default --max-expected 1 for a one-shot action), it's a race (CWE-362/367).

Concurrent-first is definitive for ONE-SHOT races (>1 concurrent effect on a fresh coupon = race).
For CONTINUOUS/lost-update races, set --max-expected to the per-request effect count (e.g. K).
The burst MUTATES state -> requires mutation_testing: approved.

Usage: python race_probe.py --url <state-change-url> [--method POST] [--data 'k=v' | --json '{"k":"v"}'] \\
        --count-url <read-metric-url> --count-regex '(\\d+)' [--concurrency 20] [--max-expected 1]
"""
import sys, json, ssl, re, argparse, urllib.request, threading
from concurrent.futures import ThreadPoolExecutor

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE

def fire(url, method, data, headers, verify):
    body = data.encode() if data else None
    h = {"User-Agent": UA, "Accept": "*/*"}; h.update(headers or {})
    if body is not None and "Content-Type" not in h:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, data=body, method=method, headers=h),
                                   timeout=20, context=(_CTX if not verify else None))
        return r.status, r.read(200).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(200).decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)

def read_count(count_url, count_regex, headers, verify):
    s, body = fire(count_url, "GET", None, headers, verify) if count_url else (None, "")
    if not body:
        return None
    m = re.search(count_regex, body)
    return int(m.group(1)) if m else None

def race(url, method, data, count_url, count_regex, concurrency, headers, verify, max_expected=1):
    baseline = read_count(count_url, count_regex, headers, verify)
    # CONCURRENT burst FIRST (the definitive race test on fresh state)
    barrier = threading.Barrier(concurrency)
    def burst():
        barrier.wait()
        fire(url, method, data, headers, verify)
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        list(ex.map(lambda _: burst(), range(concurrency)))
    after_concurrent = read_count(count_url, count_regex, headers, verify)
    concurrent_delta = (after_concurrent - baseline) if (baseline is not None and after_concurrent is not None) else None
    # serial context (what happens one-at-a-time, AFTER the concurrent consumed state)
    baseline2 = read_count(count_url, count_regex, headers, verify)
    for _ in range(concurrency):
        fire(url, method, data, headers, verify)
    after_serial = read_count(count_url, count_regex, headers, verify)
    serial_delta = (after_serial - baseline2) if (baseline2 is not None and after_serial is not None) else None
    # race = concurrent produced MORE effects than a healthy endpoint should
    raced = (concurrent_delta is not None and concurrent_delta > max_expected)
    return {"target": url, "ok": True, "concurrency": concurrency, "max_expected": max_expected,
            "baseline": baseline, "concurrent_delta": concurrent_delta, "serial_context_delta": serial_delta,
            "raced": raced,
            "findings": ([{"id": "race-condition", "severity": "high",
                           "detail": f"concurrent burst of {concurrency} produced {concurrent_delta} effect(s) (max expected {max_expected}) — the check-then-act endpoint is racy (TOCTOU); an attacker wins it with a concurrent/single-packet burst (CWE-362/367)"}] if raced else []),
            "note": "concurrent-FIRST (definitive for one-shot: >max_expected concurrent effects = race). For continuous/lost-update, set --max-expected to the per-request effect count. MUTATES state — requires mutation_testing: approved."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Single-endpoint concurrency / TOCTOU race detector")
    ap.add_argument("url", nargs="?", help="state-change URL (alias of --url; --url takes precedence if both)")
    ap.add_argument("--url", dest="url_opt"); ap.add_argument("--method", default="POST"); ap.add_argument("--data")
    ap.add_argument("--count-url"); ap.add_argument("--count-regex", default=r"(\d+)"); ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--max-expected", type=int, default=1, help="max concurrent effects for a healthy endpoint (1=one-shot; K for continuous)")
    ap.add_argument("--header", action="append", default=[]); ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    target = a.url_opt or a.url
    if not target:
        ap.error("a state-change URL is required (positional <url> or --url)")
    headers = {}
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1); headers[k.strip()] = v.strip()
    print(json.dumps(race(target, a.method, a.data, a.count_url, a.count_regex, a.concurrency, headers, not a.insecure, a.max_expected), indent=2))
