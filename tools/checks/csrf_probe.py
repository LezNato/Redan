#!/usr/bin/env python
"""csrf_probe.py — CSRF enforcement tester (control/strip/tamper/origin battery).

Tests whether a state-changing endpoint actually ENFORCES its anti-CSRF token,
using a falsifiable CONTROL: send the full request WITH the token (expect 2xx),
then re-send with the token STRIPPED / TAMPERED / Origin-mismatched. If a
stripped-token request is ACCEPTED like the control (2xx) where a 403/302/401
belonged, the token is NOT enforced = CSRF on that action. A uniform 2xx for
every payload (incl. a random-path baseline) is a WAF/SPA catch-all shell, NOT
a finding — detected and reported as inconclusive.

Usage: python csrf_probe.py <url> --method POST --data 'k=v&csrf=TOK'
       [--cookie 'k=v'] [--token-name csrf]
       [--header 'X-CSRF-Token: TOK'] [--timeout 20]

--token-name targets a BODY field (a form param in --data). For a token sent
in a request HEADER, use --header instead; the two are mutually exclusive in
practice. The battery runs its 5 probes SEQUENTIALLY (each is an independent
server-side state change, but fanning them out would add RoE/rate-limit risk
on a state-changing endpoint with no latency win worth it).
"""
import argparse, json, ssl, time, urllib.request, urllib.parse, urllib.error

# Common anti-CSRF token names (body params + header names). Order = probe order
# when the caller does not pass --token-name / --header explicitly.
TOKEN_NAMES = [
    "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
    "_csrf", "_csrf_token", "authenticity_token", "__RequestVerificationToken",
    "nonce", "token", "anticsrf", "xsrf_token", "_token",
]
HEADER_TOKEN_NAMES = [
    "X-CSRF-Token", "X-CSRFToken", "X-XSRF-TOKEN",
    "X-CSRF-Protection", "RequestVerificationToken",
]
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
# Statuses that count as ACCEPTED (the action likely proceeded) vs REJECTED.
ACCEPTED = {200, 201, 202, 204}
REJECTED = {401, 403, 404}  # 404 = endpoint expected something else; treat as not-accepted
# A 3xx to a login/error page also counts as rejection (auth/CSRF caught it).
REDIRECT = range(300, 400)


def parse_kv(s):
    """Parse 'k=v&k2=v2' into a dict. Empty -> {}."""
    out = {}
    if not s:
        return out
    for pair in s.split("&"):
        if not pair:
            continue
        if "=" in pair:
            k, v = pair.split("=", 1)
        else:
            k, v = pair, ""
        out[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
    return out


def parse_header(s):
    """Parse 'Name: value' into (name, value). Returns None if malformed."""
    if not s:
        return None
    if ":" not in s:
        return None
    name, value = s.split(":", 1)
    return name.strip(), value.strip()


def send(url, method, fields, headers, cookie, ctx, timeout):
    """Perform one request. Returns (status, body_excerpt, error, elapsed_s, final_url)."""
    t0 = time.time()
    h = dict(headers)
    h.setdefault("User-Agent", UA)
    if cookie:
        h["Cookie"] = cookie
    data = None
    target = url
    if method == "GET":
        if fields:
            sep = "&" if "?" in url else "?"
            target = url + sep + urllib.parse.urlencode(fields)
    else:
        if fields is not None:
            data = urllib.parse.urlencode(fields).encode()
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    try:
        req = urllib.request.Request(target, data=data, method=method, headers=h)
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            body = r.read(20000).decode("utf-8", errors="replace")
            return r.status, body, None, round(time.time() - t0, 2), r.geturl()
    except urllib.error.HTTPError as e:
        try:
            body = e.read(20000).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, body, None, round(time.time() - t0, 2), getattr(e, "url", target)
    except Exception as e:
        return None, "", str(e)[:120], round(time.time() - t0, 2), target


def is_accepted(status):
    """Did the action likely proceed? 2xx = yes; redirect = treat as rejected (auth/csrf catch)."""
    if status is None:
        return False
    if status in ACCEPTED:
        return True
    return False


def detect_token_name(fields, header_token):
    """Auto-detect the CSRF token param name in the body, else return None."""
    if header_token:
        return ("__header__", header_token[0])
    lc = {k.lower(): k for k in fields}
    for cand in TOKEN_NAMES:
        if cand.lower() in lc:
            return ("body", lc[cand.lower()])
    return None


def mangle(value):
    """Tamper a token value so it cannot validate (suffix + char swap)."""
    if not value:
        return "ZZINVALIDTOKENZZ"
    # flip one char + append junk so it fails any integrity check but stays same shape
    flipped = value[:-1] + ("a" if value[-1] != "a" else "b") if value else "a"
    return flipped + "zztAmPeR"


def probe(args, ctx):
    fields = parse_kv(args.data) if args.method == "POST" else parse_kv(args.data)
    if args.method == "GET" and not args.data:
        fields = {}
    header_tok = parse_header(args.header)
    cookie = args.cookie

    tok = detect_token_name(fields, header_tok) if not args.token_name else ("body", args.token_name)
    # If caller forces --token-name but it's not in the body, treat as header-style absence (we strip by header).

    # ---- Baseline: random-path benign probe (WAF/SPA catch-all shell guard) ----
    base_status, base_body, base_err, _, _ = send(
        args.url, args.method, None if args.method == "GET" else {"_csrbaseline_": "1"},
        {}, cookie, ctx, args.timeout)
    random_sep = "&" if "?" in args.url else "?"
    ghost_status, ghost_body, ghost_err, _, _ = send(
        args.url + random_sep + "csrfprobe_ghost=" + str(int(time.time())),
        "GET", None, {}, cookie, ctx, args.timeout)
    shell_suspected = False
    if (ghost_status in ACCEPTED and base_status in ACCEPTED
            and ghost_body is not None and base_body is not None
            and len(ghost_body) > 0 and ghost_body == base_body):
        shell_suspected = True

    # ---- TEST A: control (full request WITH token) ----
    ctrl_fields = dict(fields)
    ctrl_headers = {}
    if header_tok:
        ctrl_headers[header_tok[0]] = header_tok[1]
    a_status, a_body, a_err, a_t, a_final = send(
        args.url, args.method, ctrl_fields, ctrl_headers, cookie, ctx, args.timeout)
    control_ok = is_accepted(a_status)

    results = {}
    raw_results = {}

    # ---- TEST B: strip token ----
    if tok and tok[0] == "body" and tok[1] in ctrl_fields:
        b_fields = dict(ctrl_fields); del b_fields[tok[1]]
    else:
        b_fields = dict(ctrl_fields)
    b_headers = dict(ctrl_headers)
    # if token is a header (or --token-name targets a header name), strip it
    hdr_strip_name = None
    if tok and tok[0] == "__header__":
        hdr_strip_name = header_tok[0] if header_tok else None
    elif args.token_name and args.token_name.lower() in [h.lower() for h in HEADER_TOKEN_NAMES]:
        hdr_strip_name = args.token_name
    if hdr_strip_name:
        # case-insensitive removal
        for hk in list(b_headers):
            if hk.lower() == hdr_strip_name.lower():
                del b_headers[hk]
    b_status, b_body, b_err, b_t, b_final = send(
        args.url, args.method, b_fields, b_headers, cookie, ctx, args.timeout)
    strip_accepted = is_accepted(b_status)

    # ---- TEST C: tamper token value ----
    c_fields = dict(ctrl_fields)
    c_headers = dict(ctrl_headers)
    if tok and tok[0] == "body" and tok[1] in c_fields:
        c_fields[tok[1]] = mangle(c_fields[tok[1]])
    elif hdr_strip_name:
        for hk in list(c_headers):
            if hk.lower() == hdr_strip_name.lower():
                c_headers[hk] = mangle(c_headers[hk])
    c_status, c_body, c_err, c_t, c_final = send(
        args.url, args.method, c_fields, c_headers, cookie, ctx, args.timeout)
    tamper_accepted = is_accepted(c_status)

    # ---- TEST D: wrong Origin / Referer ----
    d_fields = dict(ctrl_fields)
    d_headers = dict(ctrl_headers)
    d_headers["Origin"] = "https://attacker-controlled.example"
    d_headers["Referer"] = "https://attacker-controlled.example/forged"
    d_status, d_body, d_err, d_t, d_final = send(
        args.url, args.method, d_fields, d_headers, cookie, ctx, args.timeout)
    # origin "checked" = the wrong-origin request was REJECTED (403/401/302-login) while control succeeded
    origin_checked = bool(control_ok and not is_accepted(d_status))

    # ---- SameSite note from any provided cookie ----
    samesite = None
    if cookie:
        low = cookie.lower()
        if "samesite=strict" in low:
            samesite = "Strict"
        elif "samesite=lax" in low:
            samesite = "Lax"
        elif "samesite=none" in low:
            samesite = "None"
        else:
            samesite = "not-set (browser default applies)"

    raw_results = {
        "control_A": {"status": a_status, "accepted": control_ok, "elapsed_s": a_t, "error": a_err, "final_url": a_final},
        "strip_B": {"status": b_status, "accepted": strip_accepted, "elapsed_s": b_t, "error": b_err, "final_url": b_final},
        "tamper_C": {"status": c_status, "accepted": tamper_accepted, "elapsed_s": c_t, "error": c_err, "final_url": c_final},
        "origin_D": {"status": d_status, "accepted": is_accepted(d_status), "elapsed_s": d_t, "error": d_err, "final_url": d_final},
        "baseline_ghost": {"status": ghost_status, "error": ghost_err},
    }

    # ---- Verdict (differential: B accepted while A succeeds => token not enforced) ----
    csrf_signal = bool(control_ok and strip_accepted)
    verdict = None
    note = None
    if shell_suspected and csrf_signal:
        verdict = "INCONCLUSIVE — WAF/SPA catch-all shell suspected (uniform 200 for ghost path + baseline)"
        note = ("A control 2xx and B strip 2xx look like missing enforcement, BUT a random path "
                "returned the same 200 body -> the edge serves a uniform shell to non-JS clients. "
                "Re-test through the browser channel before calling this CSRF.")
    elif csrf_signal:
        # doctrine-lint: allow CONFIRMED — paired-control proof: control WITH token succeeds and the
        # stripped-token request is STILL accepted (differential), guarded above against the WAF/SPA
        # uniform-shell false positive. The control makes non-enforcement decisive on this endpoint.
        verdict = "CSRF CONFIRMED — token stripped, action still accepted (token not enforced on this endpoint)"
        note = ("Differential: control WITH token = %s, stripped-token = %s. The server accepted the "
                "state change without the token. Rate honestly: login/logout CSRF ~Low; a security-"
                "relevant change (email/password/permission) is higher.") % (a_status, b_status)
    elif not control_ok:
        verdict = "LEAD — control request (with token) did not return 2xx; cannot establish baseline"
        note = ("Control status %s. The endpoint may require auth, a different body, a valid token "
                "value, or another header. Fix the control (cookie/data/token) before judging "
                "enforcement.") % a_status
    else:
        verdict = "ENFORCED — stripped/tampered token was rejected while the control succeeded"
        which = []
        if not strip_accepted:
            which.append("strip")
        if not tamper_accepted:
            which.append("tamper")
        note = ("Control 2xx; rejected on: %s%s. Anti-CSRF token IS enforced%s. " %
                ("+".join(which) or "(none)",
                 ", origin-checked" if origin_checked else ", origin NOT checked",
                 " and Origin/Referer validated" if origin_checked else " but Origin/Referer NOT validated (defense-in-depth gap)"))

    return {
        "target": args.url,
        "method": args.method,
        "ok": True,
        "token_name": (tok[1] if tok else None),
        "token_location": (tok[0] if tok else None),
        "control_ok": control_ok,
        "strip_accepted": strip_accepted,
        "tamper_accepted": tamper_accepted,
        "origin_checked": origin_checked,
        "samesite": samesite,
        "shell_suspected": shell_suspected,
        "verdict": verdict,
        "results": raw_results,
        "note": note,
    }


def main():
    ap = argparse.ArgumentParser(
        description="CSRF enforcement tester — control/strip/tamper/origin battery against a state-changing endpoint.")
    ap.add_argument("url", help="target URL of the state-changing endpoint")
    ap.add_argument("--method", choices=["GET", "POST"], default="POST",
                    help="HTTP method (default POST — CSRF targets state changes)")
    ap.add_argument("--data", default="",
                    help="request body 'k=v&k2=v2' including the token (POST) or query string (GET)")
    ap.add_argument("--cookie", default="", help="Cookie header value, e.g. 'session=abc'")
    ap.add_argument("--token-name", default="",
                    help="explicit CSRF token BODY field name in --data (auto-detected from common names if omitted); "
                         "for a token sent in a header, use --header instead")
    ap.add_argument("--header", default="",
                    help="token supplied as a header, e.g. 'X-CSRF-Token: TOK'")
    ap.add_argument("--timeout", type=int, default=20, help="per-request timeout (s)")
    args = ap.parse_args()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # The battery is 5 sequential probes (control, strip, tamper, origin, ghost).
    # They are independent server-side, but we run them SEQUENTIALLY: each is a
    # state-changing request, and fanning out would add RoE/rate-limit risk on a
    # state-changing endpoint for no meaningful latency win.
    out = probe(args, ctx)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
