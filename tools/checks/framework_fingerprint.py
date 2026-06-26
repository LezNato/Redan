#!/usr/bin/env python
"""framework_fingerprint.py — active server-side framework identification.

Gathers framework-distinctive signals beyond the Server: banner
(whatweb/Wappalyzer/nuclei http-technologies style). Distinct from
wp_fingerprint (WordPress-only) and browser_probe (client-side JS).

Signals: (a) headers (Server, X-Powered-By, X-AspNet-Version,
X-AspNetMvc-Version, X-Generator, Set-Cookie names) — cookie-name -> framework
map; (b) distinctive routes (/actuator/health -> Spring Boot,
/struts/webconsole.html -> Struts2, /__debug__/ -> Django, /server-status ->
Apache, /elmah.axd -> ASP.NET ELMAH, /console -> Flask/Werkzeug,
/wp-login.php -> WordPress); (c) error-signature probe of a malformed path.

FALSE-POSITIVE GUARD: an edge JS-challenge / SPA catch-all returns a uniform
200 for ANY path, so a route "reachable" + a stray signature in the challenge
shell can both read as a framework that isn't really there. We CALIBRATE
against a known-nonexistent random path: any response whose body matches the
fallback shell is tagged `fallback_shell` and is NOT counted as evidence.

Usage: python framework_fingerprint.py <url> [--no-error-probe]
       [--concurrency 6] [--timeout 12]
"""
import argparse, json, ssl, urllib.request, urllib.error, urllib.parse, hashlib
import concurrent.futures

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

# Set-Cookie name (lowercase, no value) -> framework.  Prefix-matched on the
# cookie NAME only (values can be opaque/long).
COOKIE_MAP = [
    ("jsessionid",              "Java servlet"),
    ("asp.net_sessionid",       "ASP.NET (Framework)"),
    ("aspnetcore.antiforgery",  "ASP.NET Core"),
    (".aspnetcore",             "ASP.NET Core"),
    (" phpsessid",              "PHP"),
    ("connect.sid",             "Express / Node.js"),
    ("koa:sess",                "Koa / Node.js"),
    ("_session",                "Ruby on Rails"),
    ("_rails",                  "Ruby on Rails"),
    ("laravel_session",         "Laravel (PHP)"),
    ("xsrf-token",              "Laravel (PHP)"),     # XSRF-TOKEN paired w/ laravel_session
    ("symfony",                 "Symfony (PHP)"),
    ("csrftoken",               "Django (Python)"),
    ("sessionid",               "Django (Python)"),   # Django default name
    ("play_session",            "Play Framework (Scala/Java)"),
]

# Distinctive routes. (path, framework, expect_status).
# expect_status == "non404" = a non-404 response (and non-fallback-shell) counts;
# specific status codes also accepted. The body is still checked against the
# fallback shell, so a SPA catch-all 200 won't fool us.
ROUTES = [
    ("actuator",            "Spring Boot (Actuator)",  "non404"),
    ("actuator/health",     "Spring Boot (Actuator)",  "non404"),
    ("struts/webconsole.html", "Struts2",              "non404"),
    ("__debug__/",          "Django (debug toolbar)",  "non404"),
    ("server-status",       "Apache (mod_status)",     "non404"),
    ("elmah.axd",           "ASP.NET (ELMAH)",         "non404"),
    ("trace.axd",           "ASP.NET (Trace)",         "non404"),
    ("console",             "Flask / Werkzeug (debug)", "non404"),
    ("wp-login.php",        "WordPress (note: wp_fingerprint covers it)", "non404"),
]

# Error-page signatures. Searched (case-insensitive substring) in the body of a
# malformed-path request.  (needle_lower, framework, notes)
ERROR_SIGS = [
    ("whitelabel error page",                 "Spring Boot",          "Spring whitelabel error page"),
    ("spring boot",                           "Spring Boot",          "Spring boot banner in error"),
    ("django version",                        "Django (Python)",      "Django debug page (DEBUG=True)"),
    ("traceback (most recent call last)",     "Python (generic)",     "Python traceback — see django/flask nearby"),
    ("whoops, looks like something went wrong", "Laravel (PHP)",      "Laravel default error page"),
    ("symfony",                               "Symfony (PHP)",        "Symfony error/exception page"),
    ("werkzeug",                              "Flask / Werkzeug",     "Werkzeug debugger"),
    ("<title>express",                        "Express / Node.js",    "Express default error title"),
]

MALFORMED_PATH = "redan_nonexist_%00"


def make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def sig(body):
    """Body fingerprint: short hash + length, for fallback-shell comparison."""
    b = body or b""
    return (hashlib.sha256(b).hexdigest()[:16], len(b))


def _all_set_cookie(http_message):
    """Collect EVERY Set-Cookie value from an http.client HTTPMessage.

    Duplicate headers are NOT folded to one value — a response may carry several
    Set-Cookie headers (Laravel sets laravel_session AND XSRF-TOKEN; Spring sets
    JSESSIONID alongside others). get_all returns the full list when available;
    otherwise iterate items() and gather every Set-Cookie occurrence. The dict
    built elsewhere (last value wins) would otherwise drop all but one cookie.
    """
    vals = []
    if http_message is None:
        return vals
    get_all = getattr(http_message, "get_all", None)
    if get_all is not None:
        try:
            got = get_all("set-cookie")
            if got:
                vals.extend(got)
                return vals
        except Exception:
            pass
    try:
        for k, v in http_message.items():
            if k.lower() == "set-cookie":
                vals.append(v)
    except Exception:
        pass
    return vals


def fetch(url, ctx, timeout, method="GET", max_bytes=60000):
    """Return (status, headers_dict_lower, body_bytes, error_or_None, set_cookie_list).

    set_cookie_list holds EVERY Set-Cookie value (duplicate headers preserved),
    unlike headers_dict_lower which folds duplicates to the last value.
    """
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(max_bytes)
            # http.client HTTPMessage -> dict of lowercased keys (last value wins)
            hdrs = {}
            try:
                for k, v in r.headers.items():
                    hdrs[k.lower()] = v
            except Exception:
                pass
            sc_vals = _all_set_cookie(r.headers)
            return r.status, hdrs, body, None, sc_vals
    except urllib.error.HTTPError as e:
        try:
            body = e.read(max_bytes)
        except Exception:
            body = b""
        hdrs = {}
        sc_vals = []
        try:
            if e.headers:
                for k, v in e.headers.items():
                    hdrs[k.lower()] = v
                sc_vals = _all_set_cookie(e.headers)
        except Exception:
            pass
        return e.code, hdrs, body, None, sc_vals
    except Exception as e:
        return None, {}, b"", str(e)[:120], []


def calibrate(base, ctx, timeout):
    """Probe several random nonexistent paths; collect the fallback-shell
    fingerprints (status + body-sig). A real framework signal must NOT match one
    of these.  Returns list of (status, body_sig, content_type)."""
    probes = [
        "pt-probe-nonexist-7f3a9c2e.txt",
        "pt-probe-nope-3a1b9c2e",
        "pt-probe-7c2/missing-9f1d/",
        "pt-probe-nonexist-8b4d.json",
    ]
    fallbacks = []
    for p in probes:
        url = base + p if base.endswith("/") else base + "/" + p
        status, hdrs, body, _, _ = fetch(url, ctx, timeout)
        ct = (hdrs.get("content-type") or "").split(";")[0].strip().lower()
        fallbacks.append((status, sig(body), ct))
    return fallbacks


def is_fallback_shell(status, body, fallbacks):
    """True if this response looks like the WAF/SPA catch-all (uniform 200 /
    challenge page). Compares status + body hash + length (within 3% tolerance
    to defeat per-request jitter in the shell)."""
    bs = sig(body)
    for fstatus, fbs, _ in fallbacks:
        if status != fstatus:
            continue
        if fstatus != 200:
            # any matching non-200 status on a known-nonexistent shape is itself
            # the "not found" behavior; only treat a 200 as the dangerous shell.
            continue
        if bs[0] == fbs[0]:
            return True
        # length-based near-match (shell pages can vary slightly per request)
        if abs(bs[1] - fbs[1]) <= max(256, int(fbs[1] * 0.03)):
            return True
    return False


def cookie_frameworks(set_cookie_vals):
    """Given raw Set-Cookie header values, return list of (cookie_name, framework)."""
    hits = []
    seen = set()
    for raw in set_cookie_vals:
        name_part = raw.split("=", 1)[0].strip().lower()
        if not name_part:
            continue
        for needle, fw in COOKIE_MAP:
            # leading space in needle means "word-boundary-ish prefix" used for
            # ambiguous ones (phpsessid, _session); else plain prefix on name.
            key = needle.strip()
            if name_part == key or name_part.startswith(key):
                key2 = (name_part, fw)
                if key2 not in seen:
                    seen.add(key2)
                    hits.append({"cookie": name_part, "framework": fw,
                                 "evidence": f"Set-Cookie name '{name_part}'"})
                break
    return hits


def route_worker(base, path, ctx, timeout, fallbacks):
    url = base + path if base.endswith("/") else base + "/" + path
    status, hdrs, body, err, _ = fetch(url, ctx, timeout)
    if err:
        return {"path": path, "error": err, "status": status, "fallback": False}
    shell = is_fallback_shell(status, body, fallbacks)
    # non404 AND not the catch-all shell AND a plausibly-real content-length
    real = (status and status != 404 and not shell and status < 500)
    return {"path": path, "url": url, "status": status, "fallback_shell": shell,
            "real_hit": bool(real), "body_len": len(body or b"")}


def main():
    ap = argparse.ArgumentParser(
        description="Active server-side framework identification (whatweb-style).")
    ap.add_argument("url", help="base URL (e.g. https://example.com)")
    ap.add_argument("--no-error-probe", action="store_true",
                    help="skip the malformed-path error-signature probe")
    ap.add_argument("--concurrency", type=int, default=6,
                    help="worker count for the route probes (default 6)")
    ap.add_argument("--timeout", type=float, default=12.0,
                    help="per-request timeout in seconds (default 12)")
    args = ap.parse_args()

    ctx = make_ctx()

    # normalize base url (strip trailing slash; we add paths explicitly)
    parsed = urllib.parse.urlsplit(args.url)
    base = args.url.rstrip("/")
    if not parsed.scheme:
        base = "http://" + base

    signals = []
    frameworks = {}  # name -> {"confidence", "evidence": []}

    def add_fw(name, confidence, evidence):
        if not name:
            return
        # collapse aliases that resolve to the same family
        cur = frameworks.get(name)
        if cur:
            cur["evidence"].append(evidence)
            # keep the strongest confidence seen for this name
            rank = {"low": 1, "medium": 2, "high": 3}
            if rank.get(confidence, 0) > rank.get(cur["confidence"], 0):
                cur["confidence"] = confidence
        else:
            frameworks[name] = {"confidence": confidence, "evidence": [evidence]}

    # ---- (a) headers from the root document ----
    status, hdrs, body_root, err, sc_vals = fetch(base, ctx, args.timeout)
    server_banner = None
    x_powered_by = None
    root_ok = err is None

    if root_ok:
        server_banner = hdrs.get("server")
        x_powered_by = hdrs.get("x-powered-by")
        if server_banner:
            signals.append({"type": "header", "key": "Server", "value": server_banner})
            # very loose header hints (low confidence — banners lie / are behind CDN)
            sb = server_banner.lower()
            for frag, fw in [("nginx", "nginx"),
                             ("apache", "Apache HTTP Server"),
                             ("microsoft-iis", "Microsoft IIS"),
                             ("kestrel", "ASP.NET Core (Kestrel)"),
                             ("tomcat", "Apache Tomcat (Java)"),
                             ("jetty", "Eclipse Jetty (Java)"),
                             ("gunicorn", "Gunicorn (Python WSGI)"),
                             ("werkzeug", "Flask / Werkzeug")]:
                if frag in sb:
                    add_fw(fw, "low", f"Server banner contains '{frag}'")
                    break
        if x_powered_by:
            signals.append({"type": "header", "key": "X-Powered-By", "value": x_powered_by})
            xp = x_powered_by.lower()
            for frag, fw in [("asp.net", "ASP.NET"),
                             ("express", "Express / Node.js"),
                             ("php/", "PHP"),
                             ("php ", "PHP"),
                             ("servlet", "Java servlet")]:
                if frag in xp:
                    add_fw(fw, "low", f"X-Powered-By contains '{frag}'")
                    break
        for h, fw in [("x-aspnet-version", "ASP.NET (Framework)"),
                      ("x-aspnetmvc-version", "ASP.NET MVC"),
                      ("x-generator", None)]:
            v = hdrs.get(h)
            if v:
                signals.append({"type": "header", "key": h, "value": v})
                if fw:
                    add_fw(fw, "high", f"header {h}: {v}")
                else:
                    # X-Generator is framework-y but variable (Drupal, Sitecore,
                    # Adobe AEM, etc.) — record as a medium signal, raw.
                    add_fw(f"generator: {v}", "medium", f"X-Generator: {v}")
        # Set-Cookie: check EVERY value (duplicate headers preserved in fetch),
        # not the dict-folded single value — Laravel sets laravel_session AND
        # XSRF-TOKEN; Spring sets JSESSIONID + others. Only one would survive a
        # dict, so we iterate the full list collected from the raw header.
        ck_hits = cookie_frameworks(sc_vals)
        for h in ck_hits:
            signals.append({"type": "cookie", "cookie": h["cookie"], "framework": h["framework"]})
            add_fw(h["framework"], "medium", h["evidence"])

    # ---- calibrate the fallback shell BEFORE route/error probes ----
    fallbacks = calibrate(base, ctx, args.timeout)
    shell_present = any(s == 200 for (s, _, _) in fallbacks)

    # ---- (b) distinctive routes (parallel) ----
    route_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futs = {pool.submit(route_worker, base, p, ctx, args.timeout, fallbacks): p for p in [r[0] for r in ROUTES]}
        for fut in concurrent.futures.as_completed(futs):
            route_results.append(fut.result())

    # map route -> framework for attribution
    route_fw = {r[0]: r[1] for r in ROUTES}
    for rr in sorted(route_results, key=lambda x: x.get("path", "")):
        path = rr.get("path")
        rr["framework"] = route_fw.get(path)
        if rr.get("real_hit"):
            signals.append({"type": "route", "path": path, "status": rr.get("status"),
                            "framework": route_fw.get(path), "body_len": rr.get("body_len")})
            add_fw(route_fw.get(path, "unknown"), "high",
                   f"route /{path} returned HTTP {rr.get('status')} (distinct from fallback shell)")
        elif rr.get("fallback_shell"):
            signals.append({"type": "route", "path": path, "status": rr.get("status"),
                            "fallback_shell": True,
                            "note": "matched the catch-all shell — not counted"})

    # ---- (c) error-signature probe ----
    error_hit = None
    if not args.no_error_probe:
        eurl = (base + "/" + MALFORMED_PATH) if not base.endswith("/") else (base + MALFORMED_PATH)
        estatus, ehdrs, ebody, eerr, _ = fetch(eurl, ctx, args.timeout)
        if eerr is None and not is_fallback_shell(estatus, ebody, fallbacks):
            body_lc = (ebody or b"").decode("utf-8", errors="replace").lower()
            for needle, fw, note in ERROR_SIGS:
                if needle in body_lc:
                    error_hit = {"path": "/" + MALFORMED_PATH, "status": estatus,
                                 "framework": fw, "needle": needle, "note": note}
                    signals.append({"type": "error_signature", "path": "/" + MALFORMED_PATH,
                                    "status": estatus, "framework": fw, "matched": needle})
                    add_fw(fw, "high", f"error page contained '{needle}' ({note})")
                    break  # strongest single signature is enough
        else:
            error_hit = {"path": "/" + MALFORMED_PATH, "skipped_or_shell": True,
                         "note": "error body matched fallback shell or request errored"}

    # ---- assemble output ----
    frameworks_detected = []
    for name, info in sorted(frameworks.items(), key=lambda kv: kv[0]):
        frameworks_detected.append({"name": name,
                                    "confidence": info["confidence"],
                                    "evidence": info["evidence"]})

    # build the verdict — NEVER "confirmed" unless we genuinely have distinctive
    # HIGH-confidence signals; otherwise it's a LEAD.
    high = [f for f in frameworks_detected if f["confidence"] == "high"]
    any_low = [f for f in frameworks_detected if f["confidence"] == "low"]

    if high:
        names = ", ".join(f["name"] for f in high)
        verdict = f"LEAD: distinctive framework signal — {names}"
    elif frameworks_detected:
        names = ", ".join(f["name"] for f in frameworks_detected)
        verdict = f"LEAD: weak/banners-only framework hints — {names} (banner/header-only; corroborate independently)"
    else:
        verdict = "no distinctive framework signal (generic)"

    note_parts = []
    note_parts.append("Active read-only identification. Header/cookie routes are leads — banners can "
                      "be static/CDN-fronted; a real route or error signature is stronger evidence.")
    if shell_present:
        note_parts.append("A uniform-200 fallback shell was detected on random paths — route/error "
                          "hits that matched it were discarded (WAF/SPA catch-all guard).")

    out = {
        "target": args.url,
        "ok": root_ok,
        "server_banner": server_banner,
        "x_powered_by": x_powered_by,
        "fallback_shell_detected": shell_present,
        "frameworks_detected": frameworks_detected,
        "signals": signals,
        "route_results": sorted(route_results, key=lambda x: x.get("path", "")),
        "error_probe": error_hit,
        "verdict": verdict,
        "note": " ".join(note_parts),
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
