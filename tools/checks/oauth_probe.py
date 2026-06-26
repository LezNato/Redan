#!/usr/bin/env python
"""oauth_probe.py — OAuth2/OIDC grant-flow misconfiguration analyzer.

Fetches .well-known/openid-configuration and/or
.well-known/oauth-authorization-server from an authorization server, then probes
the authorize endpoint for redirect_uri validation, state, PKCE, and
response_mode posture. jwt_probe.py inspects an issued *token*; this tool tests
the *grant flow* (the authorize request) itself.

HONESTY: this is a LEAD-grade surface prober. A redirect to an attacker host
with a code is the demonstrated code-leak surface; missing state / PKCE are
SURFACES (token-intercept / login-CSRF exposure), not account takeover on their
own. Verdict never claims ATO unless a code actually redirects to an attacker
origin. Compare every response against a benign baseline to defeat the
WAF/SPA catch-all that 200s for anything (kit pitfall).

Usage: python oauth_probe.py <base-or-issuer-url> [--client-id <id>]
       [--redirect-uri <legit>] [--authorize-url <url>] [--scope <s>]
       [--concurrency 4] [--timeout 15]
"""
import argparse, json, ssl, urllib.request, urllib.parse, urllib.error
import concurrent.futures

UA = "Mozilla/5.0 (compatible; OauthProbe/1.0)"

WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

# redirect_uri ATTACKER variants (relative to a legit --redirect-uri baseline).
# Each entry: (label, value-or-None). None => omit redirect_uri entirely.
REDIRECT_VARIANTS = [
    ("attacker.example.com", "https://attacker.example.com/cb"),
    ("victim.evil.com", "https://victim.evil.com/cb"),
    ("subdomain_suffix", "https://evil.com.victim.com/cb"),
    ("backslash_parser", "https://evil.com\\@victim.com/cb"),
    ("percent_at_parser", "https://evil.com%40victim.com/cb"),
    ("javascript_scheme", "javascript:alert(1)//"),
    ("path_traversal", None),  # handled specially: legit uri + /../open
    ("missing_redirect_uri", None),  # omit the param
]


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _origin(u):
    """Return scheme://host:port for a URL, or '' if unparseable."""
    try:
        p = urllib.parse.urlparse(u)
        if not p.scheme or not p.netloc:
            return ""
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return ""


def fetch_bytes(url, ctx, timeout=15, method="GET", body=None, headers=None,
                follow=False):
    """Return (status, headers, final_url, body_bytes, err)."""
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        # urllib follows 30x by default; disable to inspect the Location header.
        if not follow:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):
                    return None
            opener = urllib.request.build_opener(
                NoRedirect, urllib.request.HTTPSHandler(context=ctx))
            r = opener.open(req, timeout=timeout)
        else:
            r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        b = r.read(60000)
        return r.getcode(), r.headers, r.geturl(), b, None
    except urllib.error.HTTPError as e:
        try:
            b = e.read(60000)
        except Exception:
            b = b""
        return e.code, e.headers, url, b, None
    except urllib.error.URLError as e:
        return None, None, url, b"", str(e.reason)
    except Exception as e:
        return None, None, url, b"", str(e)[:120]


def fetch_metadata(base, ctx, timeout):
    """Try well-known discovery docs; return (found, metadata_dict, source_url)."""
    base = base.rstrip("/")
    # accept either a base origin or a full well-known URL
    if "/.well-known/" in base:
        urls = [base]
    else:
        urls = [base + p for p in WELL_KNOWN_PATHS]
    for u in urls:
        status, hdrs, _, b, err = fetch_bytes(u, ctx, timeout=timeout, follow=True)
        if status == 200 and b:
            try:
                doc = json.loads(b.decode("utf-8", "replace"))
                if isinstance(doc, dict) and doc:
                    return True, doc, u
            except Exception:
                continue
    return False, {}, urls[-1]


def parse_code_from_location(loc):
    """Return (code, error) parsed from a redirect Location query string."""
    if not loc:
        return None, None
    # location may be absolute or relative; fragment holds token in implicit
    try:
        qs = urllib.parse.urlparse(loc).query or loc.split("?", 1)[-1]
        frag = urllib.parse.urlparse(loc).fragment
    except Exception:
        qs, frag = loc, ""
    pairs = urllib.parse.parse_qs(qs)
    code = (pairs.get("code") or [None])[0]
    err = (pairs.get("error") or [None])[0]
    if code is None and frag:
        fpairs = urllib.parse.parse_qs(frag)
        code = (fpairs.get("code") or [None])[0]
        if err is None:
            err = (fpairs.get("error") or [None])[0]
    return code, err


def build_authorize_url(authorize_ep, params):
    sep = "&" if "?" in authorize_ep else "?"
    q = urllib.parse.urlencode(params, doseq=True)
    return f"{authorize_ep}{sep}{q}"


def probe_redirect_variant(authorize_ep, base_params, label, value,
                           legit_redirect, ctx, timeout, benign_sig):
    """Send an authorize request with the given redirect_uri variant; classify."""
    params = dict(base_params)
    notes = {}
    if label == "missing_redirect_uri":
        params.pop("redirect_uri", None)
    elif label == "path_traversal":
        # legit host, traversal path appended
        if not legit_redirect:
            return {"variant": label, "skipped": "no --redirect-uri baseline"}
        params["redirect_uri"] = legit_redirect.rstrip("/") + "/%2e%2e/open"
    else:
        if value is None:
            return {"variant": label, "skipped": "no value"}
        params["redirect_uri"] = value

    url = build_authorize_url(authorize_ep, params)
    status, hdrs, _, b, err = fetch_bytes(url, ctx, timeout=timeout)
    loc = hdrs.get("Location") if hdrs else None
    code, oauth_err = parse_code_from_location(loc)
    body_snip = (b[:300].decode("utf-8", "replace") if b else "").replace("\n", " ")

    # FALSE-POSITIVE GUARD: a uniform 200 (or uniform challenge page) for ANY
    # payload is the WAF/SPA shell, not an open redirect_uri. Compare to benign.
    shell_suspect = _shell_suspect(status, body_snip, benign_sig)

    code_issued = bool(code) and not shell_suspect
    # an attacker-scheme (javascript:) redirect with code is also a leak surface
    attacker_redirect = False
    if loc:
        lo = loc.lower()
        attacker_redirect = lo.startswith("https://attacker.example.com") or \
                            lo.startswith("https://victim.evil.com") or \
                            lo.startswith("https://evil.com.victim.com") or \
                            lo.startswith("https://evil.com") or \
                            lo.startswith("javascript:")
    # "accepted" = server issued a code to this (possibly attacker) redirect_uri
    # without surfacing an explicit OAuth error. Redundant with code_issued +
    # error, but kept as the human-readable "the server took it" flag.
    accepted = code_issued and oauth_err is None

    return {
        "variant": label,
        "status": status,
        "redirected": status in (302, 303, 307, 308),
        "location": loc[:200] if loc else None,
        "code_issued": code_issued,
        "code_prefix": (code[:8] + "...") if code else None,
        "error": oauth_err,
        "attacker_origin": attacker_redirect,
        "shell_suspect": shell_suspect,
        "accepted": accepted,
        "body_snippet": body_snip[:160],
        "url": url,
        "err": err,
    }


def _shell_suspect(status, body_snip, benign_sig):
    """Heuristic: same status + near-identical body to a random benign request
    => WAF/JS-challenge shell, not a real app response."""
    if benign_sig is None:
        return False
    b_status, b_len, b_head = benign_sig
    if status != b_status:
        return False
    # same status and the leading body bytes are byte-identical to benign => shell
    if body_snip[:80] == b_head[:80] and len(body_snip) > 0:
        return True
    return False


def benign_baseline(authorize_ep, base_params, ctx, timeout):
    """Hit the authorize endpoint with a random/nonexistent state + nonexistent
    client to capture the 'shell' / SPA / login-wall signature."""
    import random, string
    rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    params = dict(base_params)
    params["state"] = rnd + "_benign_probe"
    url = build_authorize_url(authorize_ep, params)
    status, hdrs, _, b, err = fetch_bytes(url, ctx, timeout=timeout)
    head = (b[:120].decode("utf-8", "replace") if b else "").replace("\n", " ")
    return (status, len(b), head)


def main():
    ap = argparse.ArgumentParser(
        description="OAuth2/OIDC grant-flow misconfiguration analyzer (LEAD-grade).")
    ap.add_argument("url", help="authorization-server base URL or issuer URL "
                  "(e.g. https://auth.example.com)")
    ap.add_argument("--client-id", default="", help="client_id to use in authorize "
                  "requests (use a test/dummy client if unknown)")
    ap.add_argument("--redirect-uri", default="", help="a LEGIT registered "
                  "redirect_uri to use as the benign baseline origin")
    ap.add_argument("--authorize-url", default="", help="explicit authorize "
                  "endpoint (overrides discovery / .well-known)")
    ap.add_argument("--scope", default="openid profile", help="scope string")
    ap.add_argument("--response-type", default="code", help="response_type "
                  "(default 'code'; use 'token' to probe implicit/fragment flow)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args()
    ctx = _ctx()

    # ---- 1. metadata discovery ----
    metadata_found, metadata, meta_src = fetch_metadata(args.url, ctx, args.timeout)

    # ---- 2. resolve authorize endpoint ----
    authorize_ep = args.authorize_url
    if not authorize_ep:
        authorize_ep = (metadata.get("authorization_endpoint")
                        or metadata.get("authorize_endpoint"))
    issues = []
    if not authorize_ep:
        # fall back to a conventional path on the given base origin
        o = _origin(args.url) or args.url.rstrip("/")
        authorize_ep = o + "/authorize"
        issues.append(f"no authorize_endpoint discovered; using conventional {authorize_ep}")

    if not authorize_ep.startswith(("http://", "https://")):
        authorize_ep = "https://" + authorize_ep

    # ---- 3. base params ----
    client_id = args.client_id or metadata.get("client_id") or "oauth_probe_test"
    legit_redirect = args.redirect_uri or metadata.get("redirect_uri") or ""
    base_params = {
        "response_type": args.response_type,
        "client_id": client_id,
        "scope": args.scope,
    }
    if legit_redirect:
        base_params["redirect_uri"] = legit_redirect

    # ---- 4. benign baseline (shell / SPA / login-wall signature) ----
    benign_sig = benign_baseline(authorize_ep, base_params, ctx, args.timeout)

    # ---- 5. redirect_uri variants ----
    redirect_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {
            pool.submit(probe_redirect_variant, authorize_ep, base_params,
                        label, value, legit_redirect, ctx, args.timeout,
                        benign_sig): label
            for label, value in REDIRECT_VARIANTS
        }
        for fut in concurrent.futures.as_completed(futures):
            try:
                redirect_results.append(fut.result())
            except Exception as e:
                redirect_results.append({"variant": futures[fut], "err": str(e)[:120]})
    redirect_results.sort(key=lambda r: r.get("variant", ""))

    # ---- 6. state probe (no state in request) ----
    no_state_params = dict(base_params)
    no_state_params.pop("state", None)
    # send WITHOUT state; classify by whether the server still issues a code
    st_url = build_authorize_url(authorize_ep, no_state_params)
    st_status, st_hdrs, _, st_b, st_err = fetch_bytes(st_url, ctx, timeout=args.timeout)
    st_loc = st_hdrs.get("Location") if st_hdrs else None
    st_code, st_oauth_err = parse_code_from_location(st_loc)
    st_shell = _shell_suspect(st_status, (st_b[:300].decode("utf-8","replace")).replace("\n"," "),
                              benign_sig)
    # state_required is only meaningful when the request actually reached a
    # server and returned an explicit OAuth response (an error, or a code). A
    # totally failed request (status None / connection-refused / shell) carries
    # no signal about the server's state enforcement -> null/unknown, NOT True.
    state_required = None
    reached = st_status is not None and not st_shell
    if reached:
        if st_oauth_err:
            # server returned an explicit OAuth error -> it enforces *something*.
            state_required = True
        elif st_code and st_oauth_err is None:
            # server issued a code with no state param and no error -> state is
            # NOT enforced (login-CSRF / state-fixation surface).
            state_required = False
            issues.append("state parameter not required: server issued a code "
                          "without state (login-CSRF / state-fixation surface)")
    state_test = {
        "status": st_status, "redirected": st_status in (302,303,307,308),
        "location": st_loc[:200] if st_loc else None,
        "code_issued": bool(st_code) and not st_shell,
        "error": st_oauth_err, "shell_suspect": st_shell,
        "state_required": state_required,
    }

    # ---- 7. PKCE probe (no code_challenge in request) ----
    pkce_params = dict(base_params)  # no code_challenge/code_challenge_method
    pk_url = build_authorize_url(authorize_ep, pkce_params)
    pk_status, pk_hdrs, _, pk_b, pk_err = fetch_bytes(pk_url, ctx, timeout=args.timeout)
    pk_loc = pk_hdrs.get("Location") if pk_hdrs else None
    pk_code, pk_oauth_err = parse_code_from_location(pk_loc)
    pk_shell = _shell_suspect(pk_status, (pk_b[:300].decode("utf-8","replace")).replace("\n"," "),
                              benign_sig)
    pkce_required = False
    if pk_oauth_err or (pk_code is None and not pk_shell and pk_status in (400, 401, 403)):
        pkce_required = True
    elif bool(pk_code) and not pk_shell and pk_oauth_err is None:
        pkce_required = False
        issues.append("PKCE not enforced: server issued a code without "
                      "code_challenge (token-intercept surface on public clients)")
    pkce_test = {
        "status": pk_status, "redirected": pk_status in (302,303,307,308),
        "location": pk_loc[:200] if pk_loc else None,
        "code_issued": bool(pk_code) and not pk_shell,
        "error": pk_oauth_err, "shell_suspect": pk_shell,
        "pkce_required": pkce_required,
    }

    # ---- 8. response_mode / implicit token-in-fragment note ----
    response_mode_note = None
    if args.response_type in ("token", "id_token", "token id_token"):
        response_mode_note = ("implicit/fragment flow: tokens land in the URL "
                              "fragment (referer/browser-history leakage surface)")
        issues.append(response_mode_note)

    # ---- 9. classify the strong signal: code issued to an attacker origin ----
    attacker_code_leak = [r for r in redirect_results
                          if r.get("code_issued") and r.get("attacker_origin")
                          and not r.get("shell_suspect")]
    redirect_weak = [r for r in redirect_results
                     if r.get("code_issued") and not r.get("attacker_origin")
                     and not r.get("shell_suspect")]

    if attacker_code_leak:
        verdict = "OAUTH CODE-LEAK SURFACE: authorize redirected a code to an attacker-controlled origin"
    elif redirect_weak or (not state_required and st_code) or (not pkce_required and pk_code):
        verdict = "OAUTH MISCONFIGURATION LEAD: weak redirect_uri/state/PKCE posture (surfaces, not ATO)"
    elif metadata_found:
        verdict = "no obvious OAuth grant-flow misconfiguration (metadata found)"
    else:
        verdict = "no OAuth discovery metadata and no exploitable flow observed"

    note_parts = []
    if benign_sig and benign_sig[0] == 200:
        note_parts.append("benign baseline returned 200 (possible SPA/login-shell) "
                          "so code_issued flags were shell-guarded")
    note_parts.append("LEAD-grade: a code to an attacker origin = code-leak surface; "
                      "missing state/PKCE = surfaces, not ATO.")
    note = " ".join(note_parts)

    # ok = we actually reached something meaningful: discovery metadata landed,
    # or at least one authorize redirect probe returned a real status. If every
    # request failed (no metadata, all statuses null), ok is False rather than a
    # fabricated True.
    ok = bool(metadata_found) or any(r.get("status") for r in redirect_results)

    out = {
        "target": args.url,
        "ok": ok,
        "metadata_found": metadata_found,
        "metadata_source": meta_src if metadata_found else None,
        "metadata": metadata if metadata_found else {},
        "authorize_endpoint": authorize_ep,
        "client_id_used": client_id,
        "redirect_uri_baseline": legit_redirect or "(none provided)",
        "redirect_uri_tests": redirect_results,
        "state_test": state_test,
        "state_required": state_required,
        "pkce_test": pkce_test,
        "pkce_required": pkce_required,
        "response_mode_note": response_mode_note,
        "attacker_code_leak": attacker_code_leak,
        "issues": issues,
        "verdict": verdict,
        "note": note,
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
