#!/usr/bin/env python
"""rate_limit_test.py — rate-limit / brute-protection DETECTOR (API4:2023), stdlib only.

NOT a credential-stuffing weapon. Detects WHETHER an endpoint enforces a rate
limit and, if so, the threshold/reset behavior; or reports its ABSENCE on a
sensitive surface (the brute-force / OTP-bomb / credential-stuffing enabler).

Method: baseline one request, then send --count requests (--gap seconds apart,
serial by default; --concurrency > 1 for a parallel burst) and watch for the
throttle signal:
  - status 429 (Too Many Requests), or a 403/423 lockout that appears MID-burst
  - a Retry-After header (value captured)
  - a body marker ('too many requests', 'rate limit', 'temporarily', 'locked',
    'blocked', 'captcha', 'try again later', 'throttle')
  - a latency spike (a soft throttle that delays instead of rejecting)

Verdict:
  throttled     -> INFORMATIONAL (a control is present; report threshold + reset)
  not throttled -> LEAD on a SENSITIVE endpoint (login/OTP/password-reset/2FA/
                  token/state-change): enables brute force / stuffing / OTP
                  bombing. Severity depends on endpoint SENSITIVITY — the agent
                  judges. An unthrottled PUBLIC GET is usually by-design, not a bug.

HONEST CEILING (coverage_gap): if the throttled surface is AUTHENTICATED (e.g. a
login throttle that only fires for a REAL account) and we test anon, we cannot
fully enumerate it -> coverage_gap emitted. For login tests use a likely-
NONEXISTENT username so you do not lock a real account.

RoE: a burst resembles load. Bounded --count (default 60, hard-capped at 500),
gentle on production (scope.yaml production:true -> use a low count + run
health_check between batches). NEVER feed a real password list (that's stuffing,
not detection). DoS / exhaustion is OUT OF SCOPE regardless of authorization.

Usage:
  python rate_limit_test.py <url> [--method POST] [--data 'username=nobody&pw=x']
        [--count 60] [--gap 0.05] [--concurrency 1] [--marker 'too many requests']
        [--header "Cookie: ..."] [--insecure] [--timeout 10]
"""
import sys, os, re, ssl, json, time, argparse, urllib.request, urllib.parse, urllib.error
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _concurrency import workers

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE

DEFAULT_MARKERS = ["too many requests", "rate limit", "rate-limit", "temporarily",
                   "locked", "blocked", "captcha", "try again later", "throttl",
                   "too many login", "too many attempts"]
THROTTLE_STATUS = {429}
LOCK_STATUS = {403, 423}
AUTH_SURFACE_RE = re.compile(r"(login|signin|sign-in|log-in|auth|otp|2fa|mfa|password|reset|token|account|verify)", re.I)
HARD_CAP = 500


def _req(url, method, data, headers, timeout, verify):
    body = data.encode() if data else None
    h = {"User-Agent": UA, "Accept": "*/*"}
    if body is not None and "Content-Type" not in {k.lower() for k in headers}:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    h.update(headers or {})
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=(_CTX if not verify else None)) as r:
            dt = time.perf_counter() - t0
            return r.status, dt, {k.lower(): v for k, v in r.headers.items()}, r.read(3000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        dt = time.perf_counter() - t0
        return e.code, dt, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read(3000).decode("utf-8", "replace")
    except Exception as e:
        return None, time.perf_counter() - t0, {}, str(e)


def _is_throttle(status, body, markers, baseline_status):
    """429 is definitive; 403/423/503 count only if they CHANGE mid-burst or carry
    a marker (a uniformly-403 auth-required endpoint must NOT read as 'throttled')."""
    b = (body or "").lower()
    if status in THROTTLE_STATUS:
        return True
    if status in LOCK_STATUS and baseline_status not in LOCK_STATUS:
        return True
    if status in LOCK_STATUS and any(m in b for m in markers):
        return True
    if any(m in b for m in markers):
        return True
    return False


def run(url, method, data, headers, count, gap, concurrency, markers, timeout, verify):
    count = max(1, min(count, HARD_CAP))
    out = {"target": url, "method": method, "count": count, "ok": True}

    bs, bt, bh, bb = _req(url, method, data, headers, timeout, verify)
    out["baseline"] = {"status": bs, "latency_ms": round(bt * 1000)}

    statuses = {}
    latencies = []
    first_throttle = None
    retry_after = None
    markers_hit = []

    def one(i):
        nonlocal first_throttle, retry_after
        if gap and concurrency <= 1:
            time.sleep(gap)
        s, dt, h, b = _req(url, method, data, headers, timeout, verify)
        latencies.append(dt)
        statuses[s] = statuses.get(s, 0) + 1
        ra = h.get("retry-after")
        if ra and retry_after is None:
            retry_after = ra
        for m in markers:
            if m in (b or "").lower() and m not in markers_hit:
                markers_hit.append(m)
        if first_throttle is None and _is_throttle(s, b, markers, bs):
            first_throttle = i + 1

    if concurrency > 1:
        with ThreadPoolExecutor(max_workers=workers(io_bound=True, want=concurrency)) as ex:
            list(ex.map(one, range(count)))
    else:
        for i in range(count):
            one(i)

    throttled = first_throttle is not None
    sorted_lat = sorted(latencies) if latencies else [0]
    med = sorted_lat[len(sorted_lat) // 2]
    lat_min, lat_max = (sorted_lat[0], sorted_lat[-1]) if latencies else (0, 0)
    latency_spike = bool(latencies) and med > max(bt * 3, 1.0) and not throttled

    out["throttled"] = throttled
    out["first_throttle_at"] = first_throttle
    out["statuses"] = {str(k): v for k, v in sorted(statuses.items(), key=lambda kv: -kv[1])}
    out["retry_after"] = retry_after
    out["markers_hit"] = markers_hit
    out["latency"] = {"min_ms": round(lat_min * 1000), "max_ms": round(lat_max * 1000),
                      "median_ms": round(med * 1000), "spike_without_reject": latency_spike}

    findings = []
    if throttled:
        findings.append({"id": "rate-limit-present", "severity": "info",
                         "detail": ("Endpoint throttles requests — first throttle at request #%s%s. "
                                    "A brute-force control IS present (informational, not a vuln)."
                                    % (first_throttle,
                                       (", Retry-After " + str(retry_after)) if retry_after else ""))})
    else:
        sev = "medium" if (AUTH_SURFACE_RE.search(url) or (data and AUTH_SURFACE_RE.search(data))) else "low"
        spike_note = (" A latency spike without rejection was observed (median %.0fms vs baseline %.0fms) "
                      "— possibly a soft/delay throttle worth a longer run." % (med * 1000, bt * 1000)
                      ) if latency_spike else ""
        findings.append({"id": "no-rate-limit", "severity": sev,
                         "detail": ("%d requests returned no 429 / throttle / lockout%s — no rate "
                                    "limiting observed on this surface. On a SENSITIVE endpoint "
                                    "(login/OTP/password-reset/2FA/state-change) this enables brute "
                                    "force / credential stuffing / OTP bombing; severity depends on "
                                    "endpoint sensitivity (the agent judges). An unthrottled public "
                                    "GET is usually by-design, not a bug." % (count, spike_note))})
    out["findings"] = findings

    # coverage_gap: an auth/login surface tested without valid creds — the real
    # throttle may be per-account and invisible to an anon/invalid-cred probe.
    if AUTH_SURFACE_RE.search(url) or (data and AUTH_SURFACE_RE.search(data)):
        out["coverage_gap"] = True
        out["coverage_gap_reason"] = ("This looks like an auth/login surface tested without valid "
                                      "credentials. Many throttles fire PER ACCOUNT (or only for a real "
                                      "username); an anon / nonexistent-user probe may not trigger it. "
                                      "Treat 'not throttled' here as a LEAD, not a confirmed absence — "
                                      "confirm with a provisioned TEST account (auth-tester).")
    out["note"] = ("DETECTOR, not a stuffer: sends benign/identical requests only — never feed a real "
                   "password list. Bounded count (cap %d). On production (scope.yaml production:true) use "
                   "a low --count and run health_check between batches; DoS/exhaustion is out of scope. "
                   "For login tests use a NONEXISTENT username to avoid locking a real account."
                   % HARD_CAP)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Rate-limit / brute-protection detector (API4:2023)")
    ap.add_argument("url")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--data", help="request body, query-string encoded")
    ap.add_argument("--count", type=int, default=60)
    ap.add_argument("--gap", type=float, default=0.0, help="seconds between serial requests")
    ap.add_argument("--concurrency", type=int, default=1, help=">1 => parallel burst (uses _concurrency)")
    ap.add_argument("--marker", action="append", default=[], help="extra throttle body-marker (repeatable)")
    ap.add_argument("--header", action="append", default=[], help="extra header, 'Name: value'")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    headers = {}
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1); headers[k.strip()] = v.strip()
    markers = list(dict.fromkeys(DEFAULT_MARKERS + a.marker))  # de-dup, preserve order
    print(json.dumps(run(a.url, a.method, a.data, headers, a.count, a.gap, a.concurrency,
                         markers, a.timeout, not a.insecure), indent=2))
