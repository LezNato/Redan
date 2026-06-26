#!/usr/bin/env python
"""csp_probe.py — Content-Security-Policy directive analyzer (Google CSP Evaluator style).

Fetches the Content-Security-Policy response header for a URL (or accepts a raw
policy string via --policy), parses directives (split on ";", each = name +
space-separated sources), and flags bypassable/weak patterns: unsafe-inline/
unsafe-eval, bare wildcards, JSONP/known-bypass allowlist hosts, missing
object-src/base-uri, nonce+unsafe-inline conflicts, mixed http: sources.

Usage: python csp_probe.py <url> [--header "Cookie: ..."]
       python csp_probe.py --policy "<raw-csp-string>"
"""
import argparse, json, urllib.request, urllib.error, ssl

# CSP keywords are single-QUOTE-delimited tokens ('unsafe-inline', 'unsafe-eval',
# 'nonce-...', 'sha256-...', 'none'). Membership tests MUST compare against the
# quoted forms — comparing the bare unquoted literal never matches a parsed
# source (silent false-negative on the primary XSS-viable detector).
UNSAFE_INLINE = chr(39) + "unsafe-inline" + chr(39)
UNSAFE_EVAL = chr(39) + "unsafe-eval" + chr(39)

# Known JSONP / CDN / allowlist hosts that make a CSP script-src trivially
# bypassable even without unsafe-inline (Google CSP Evaluator "bypass" list).
BYPASS_HOSTS = [
    "*.googleapis.com",
    "googleapis.com",
    "cdn.jsdelivr.net",
    "*.jquery.com",
    "jquery.com",
    "ajax.googleapis.com",
    "accounts.google.com",
    "fonts.googleapis.com",
    "www.youtube.com",
    "*.ytimg.com",
    "gist.github.com",
    "cdnjs.cloudflare.com",
    "unpkg.com",
]

# Directives that, if missing, get an "undefined-src" fallback note.
FETCH_DIRECTIVES = [
    "script-src", "object-src", "style-src", "img-src", "connect-src",
    "font-src", "frame-src", "media-src", "manifest-src", "worker-src",
]


def parse_csp(raw):
    """Parse a raw CSP header into {directive: [sources]}. Lowercase names."""
    directives = {}
    if not raw:
        return directives
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        sources = [t.lower() for t in tokens[1:]]
        directives[name] = sources
    return directives


def effective(directives, name):
    """Return sources for a fetch directive, falling back to default-src."""
    if name in directives:
        return directives[name]
    return directives.get("default-src", [])


def analyze(directives):
    """Return list of issue dicts: {directive, problem, severity}."""
    issues = []
    has_default = "default-src" in directives
    has_csp = len(directives) > 0

    # 1. No CSP at all and no default-src -> XSS unprotected
    if not has_csp:
        issues.append({"directive": "(none)",
                       "problem": "no Content-Security-Policy header present",
                       "severity": "high"})
        return issues

    if not has_default and "script-src" not in directives:
        issues.append({"directive": "default-src",
                       "problem": "no default-src and no script-src — script execution unrestricted",
                       "severity": "high"})

    script = effective(directives, "script-src")
    obj = effective(directives, "object-src")
    style = effective(directives, "style-src")

    # 2. unsafe-inline / unsafe-eval in script-src or default-src
    for dname, srcs in [("script-src", script), ("default-src", directives.get("default-src", []))]:
        if UNSAFE_INLINE in srcs:
            issues.append({"directive": dname,
                           "problem": "'unsafe-inline' present — inline script XSS viable",
                           "severity": "high"})
        if UNSAFE_EVAL in srcs:
            issues.append({"directive": dname,
                           "problem": "'unsafe-eval' present — eval-based XSS viable",
                           "severity": "medium"})

    # 3. bare wildcard "*" in script-src / object-src / style-src
    for dname, srcs in [("script-src", script), ("object-src", obj), ("style-src", style)]:
        if "*" in srcs:
            issues.append({"directive": dname,
                           "problem": "bare wildcard '*' — trivial CSP bypass",
                           "severity": "high"})

    # 4. JSONP / known-bypass allowlist hosts in script-src
    matched_bypass = []
    for host in BYPASS_HOSTS:
        for s in script:
            # exact or wildcard-domain match
            if s == host or (host.startswith("*.") and (s == host[2:] or s.endswith(host[1:]))):
                if host not in matched_bypass:
                    matched_bypass.append(host)
    if matched_bypass:
        issues.append({"directive": "script-src",
                       "problem": f"known-bypass / JSONP allowlist host(s): {', '.join(matched_bypass)}",
                       "severity": "medium"})

    # 5. object-src missing or not 'none' -> plugin/flash surface
    if "object-src" not in directives and "default-src" not in directives:
        issues.append({"directive": "object-src",
                       "problem": "object-src undefined (and no default-src) — plugin/Flash surface open",
                       "severity": "low"})
    elif "'none'" not in obj:
        issues.append({"directive": "object-src",
                       "problem": "object-src allows plugin content (not 'none')",
                       "severity": "low"})

    # 6. base-uri missing -> base-hijack
    if "base-uri" not in directives:
        issues.append({"directive": "base-uri",
                       "problem": "base-uri undefined — <base> hijack surface",
                       "severity": "low"})

    # 7. both nonce and unsafe-inline present -> nonce negated
    has_nonce = any(s.startswith("'nonce-") for s in script)
    has_hash = any(s.startswith("'sha") for s in script)
    if has_nonce and UNSAFE_INLINE in script:
        issues.append({"directive": "script-src",
                       "problem": "both nonce and 'unsafe-inline' present — nonces may be negated",
                       "severity": "medium"})
    if has_hash and UNSAFE_INLINE in script:
        issues.append({"directive": "script-src",
                       "problem": "both hash and 'unsafe-inline' present — inline still allowed",
                       "severity": "medium"})

    # 8. report-uri / report-to (info)
    if "report-uri" in directives or "report-to" in directives:
        issues.append({"directive": "report-uri" if "report-uri" in directives else "report-to",
                       "problem": "reporting configured (violation reporting on)",
                       "severity": "info"})

    # 9. mixed http: sources in an https context
    all_srcs = [s for srcs in directives.values() for s in srcs]
    http_sources = [s for s in all_srcs if s.startswith("http:")]
    if http_sources:
        issues.append({"directive": "(mixed)",
                       "problem": f"plain http: source(s) present: {', '.join(http_sources[:5])}",
                       "severity": "info"})

    return issues


def verdict_for(directives, issues):
    if not directives:
        return "CSP ABSENT — XSS unprotected"
    severities = [i["severity"] for i in issues]
    if "high" in severities:
        return "CSP WEAK/BYPASSABLE — XSS viable"
    if "medium" in severities:
        return "CSP present, no obvious bypass"
    # only low/info or nothing -> strong-ish
    if not issues or all(s in ("info", "low") for s in severities):
        return "CSP strong"
    return "CSP present, no obvious bypass"


def fetch_csp(url, extra_header, ctx, timeout):
    """Fetch a URL and return (status, raw_csp_header_or_None, error_or_None)."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"})
    if extra_header:
        name, _, val = extra_header.partition(":")
        req.add_header(name.strip(), val.strip())
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            # headers may have multiple CSP entries; join them
            csp = r.headers.get("Content-Security-Policy")
            return r.status, csp, None
    except urllib.error.HTTPError as e:
        csp = e.headers.get("Content-Security-Policy") if e.headers else None
        return e.code, csp, None
    except Exception as e:
        return None, None, str(e)[:160]


def main():
    ap = argparse.ArgumentParser(description="Content-Security-Policy directive analyzer")
    ap.add_argument("url", nargs="?", help="target URL to fetch the CSP header from")
    ap.add_argument("--policy", default=None, help="raw CSP policy string to analyze (skips fetch)")
    ap.add_argument("--header", default=None, help="extra request header, e.g. 'Cookie: sess=...'")
    ap.add_argument("--timeout", type=int, default=15, help="per-request timeout (s)")
    args = ap.parse_args()

    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

    if args.policy is not None:
        raw_policy = args.policy
        target = "(--policy)"
        status = None
        fetch_err = None
    else:
        if not args.url:
            ap.error("either a target URL or --policy is required")
        target = args.url
        # CSP analysis is HEADER-ONLY: fetch_csp does a single urlopen of the
        # target URL and reads the Content-Security-Policy response header.
        status, raw_policy, fetch_err = fetch_csp(args.url, args.header, ctx, args.timeout)

    directives = parse_csp(raw_policy)
    policy_present = bool(directives)
    issues = analyze(directives)
    verdict = verdict_for(directives, issues)

    note = ("header fetched + directive-analyzed. Verdict reflects bypassable/weak patterns only — "
            "no active payload delivered; this is a config-read LEAD, not an executed exploit.")

    print(json.dumps({
        "target": target,
        "ok": fetch_err is None,
        "status": status,
        "policy_present": policy_present,
        "raw_policy": raw_policy,
        "directives": directives,
        "issues": issues,
        "verdict": verdict,
        "note": note,
    }, indent=2))


if __name__ == "__main__":
    main()
