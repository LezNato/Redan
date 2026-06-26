#!/usr/bin/env python
"""health_check.py — production-site safety tool.

Protects a LIVE target from the assessment: establish a health baseline, then
check between active-testing batches and signal **ABORT** if the target degrades
(5xx / unreachable / latency blowup) or if you are being WAF-blocked / rate-
limited / locked out. The orchestrator + finder agents call `check` between
batches and STOP on abort (don't keep hammering a struggling prod site).

Usage:
  python health_check.py baseline <url> [--samples 5]        # -> baseline JSON (save it)
  python health_check.py check <url> --baseline-file <f>      # -> healthy / ABORT verdict
  python health_check.py check <url> --baseline '<json>' [--latency-factor 4]
"""
import sys, re, json, ssl, time, argparse, urllib.request, urllib.error, statistics

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
WAF_SIGNS = ["access denied", "request blocked", "attention required", "captcha",
             "are you a robot", "mod_security", "incapsula", "imperva", "akamai",
             "you have been blocked", "rate limit", "too many requests"]
BLOCK_STATUS = {401: "auth", 403: "forbidden/WAF", 406: "WAF", 429: "rate-limited", 503: "unavailable/WAF"}

def sample(url, timeout=15):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    t = time.perf_counter()
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = r.read(8000); code = r.getcode(); hdrs = dict(r.headers)
    except urllib.error.HTTPError as e:
        body = b""; code = e.code; hdrs = dict(e.headers or {})
    except Exception as e:
        return {"ok": False, "status": None, "latency_ms": None, "error": str(e), "body": "", "headers": {}}
    return {"ok": True, "status": code, "latency_ms": round((time.perf_counter() - t) * 1000),
            "body": body.decode("latin-1", "replace")[:8000], "headers": hdrs}

def detect_block(s):
    st = s.get("status")
    h = {k.lower(): v for k, v in (s.get("headers") or {}).items()}
    if st in BLOCK_STATUS:
        return f"HTTP {st} ({BLOCK_STATUS[st]})"
    if "retry-after" in h:
        return f"Retry-After header present ({h['retry-after']})"
    low = (s.get("body") or "").lower()
    for sign in WAF_SIGNS:
        if sign in low:
            return f"WAF/block signature in body ('{sign}')"
    return None

def baseline(url, samples=5):
    rows = []
    for _ in range(samples):
        rows.append(sample(url)); time.sleep(0.3)
    lats = [r["latency_ms"] for r in rows if r.get("latency_ms") is not None]
    ok = [r for r in rows if r.get("ok") and (r.get("status") or 500) < 500]
    statuses = [r.get("status") for r in rows]
    return {"url": url, "samples": samples, "ok_rate": round(len(ok) / samples, 2),
            "median_latency_ms": int(statistics.median(lats)) if lats else None,
            "status_mode": max(set(statuses), key=statuses.count) if statuses else None}

def check(url, base, latency_factor=4.0):
    s = sample(url)
    degraded, block = [], detect_block(s)
    if not s.get("ok") or s.get("status") is None:
        degraded.append(f"unreachable ({s.get('error')})")
    elif s["status"] >= 500:
        degraded.append(f"server error HTTP {s['status']}")
    bl = base.get("median_latency_ms")
    if bl and s.get("latency_ms") and s["latency_ms"] > max(2000, bl * latency_factor):
        degraded.append(f"latency blowup {s['latency_ms']}ms vs baseline {bl}ms (>{latency_factor}x)")
    abort = bool(degraded) or bool(block)
    return {"target": url, "ok": True, "abort": abort, "healthy": not abort,
            "status": s.get("status"), "latency_ms": s.get("latency_ms"),
            "baseline_latency_ms": bl, "degraded": degraded, "block_reason": block,
            "action": ("ABORT active testing and back off — the live target is degraded or blocking you"
                       if abort else "ok to continue")}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["baseline", "check"])
    ap.add_argument("url")
    ap.add_argument("--samples", type=int, default=5)
    ap.add_argument("--baseline"); ap.add_argument("--baseline-file")
    ap.add_argument("--latency-factor", type=float, default=4.0)
    a = ap.parse_args()
    if a.mode == "baseline":
        print(json.dumps(baseline(a.url, a.samples), indent=2)); return
    base = {}
    if a.baseline_file:
        base = json.load(open(a.baseline_file, encoding="utf-8"))
    elif a.baseline:
        base = json.loads(a.baseline)
    out = check(a.url, base, a.latency_factor)
    print(json.dumps(out, indent=2))
    sys.exit(2 if out["abort"] else 0)   # exit 2 = ABORT (orchestrator/hook can gate on it)

if __name__ == "__main__":
    main()
