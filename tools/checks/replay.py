#!/usr/bin/env python
"""replay.py — raw-HTTP transaction replay + response-diff (stdlib only; verifier/evidence utility).

Replays a captured raw HTTP request against a target and (optionally) diffs the observed
response against a captured/expected one — verifier-grade EXACT-BYTE reproduction.

Why it exists: the kit's tools each capture their own structured I/O and the verifier
re-runs a probe to reproduce. But findings reached through the BROWSER channel (WAF'd
sites, SPAs — this kit's proven hard case) or complex authed flows are hard to re-derive
faithfully; replaying the captured request verbatim is. It also gives the client deliverable
the exact request/response bytes (evidence fidelity).

NOT a MITM proxy and does no TLS interception. It REPLAYS a transcript regardless of how it
was captured (browser devtools "Copy as HTTP", a Playwright network capture, a tool's JSON
evidence, or hand-written). Full TLS-intercepting CAPTURE needs mitmproxy (deferred — heavy
dep; see coverage-matrix). This tool is the replay+diff half of that idea, stdlib-only.

HONEST CEILINGS:
  - Authed requests go STALE: a captured Bearer/session replayed later often 401s because the
    token rotated. A 401/403 on replay of an authed request is flagged "stale credential?"
    NOT "not reproduced." Use --reauth-header/--reauth-cookie to substitute a fresh token.
  - Dynamic fields (Date, Set-Cookie, CSRF nonces, ETag) legitimately differ between runs;
    pass them to --normalize so the diff doesn't false-flag "changed."
  - Strips hop-by-hop headers (Host/Content-Length/Connection) on replay; urllib re-sets them.

Transcript format (request line + headers + blank line + body; optional ===RESPONSE=== + the
captured response):
  POST /api/orders/123 HTTP/1.1
  Host: target.example
  Authorization: Bearer <redacted>
  Content-Type: application/json

  {"id":123}
  ===RESPONSE===
  HTTP/1.1 200 OK
  Content-Type: application/json

  {"order":{"id":123,"owner":"alice"}}

Usage:
  python replay.py --transcript req.txt [--target https://host] [--diff]
        [--reauth-header "Authorization: Bearer FRESH"] [--reauth-cookie "s=FRESH"]
        [--normalize date,set-cookie,csrf-token,etag] [--redact] [--insecure] [--timeout 15]
"""
import sys, json, re, ssl, hashlib, argparse, urllib.request, urllib.error, urllib.parse

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE
HOP_BY_HOP = {"host", "content-length", "connection", "accept-encoding", "transfer-encoding", "keep-alive", "proxy-connection", "upgrade"}
SECRET_HDR = re.compile(r"^(authorization|cookie|set-cookie|x-api-key|x-csrf-token|x-xsrf-token)\b", re.I)


def _mask(name, val):
    return ("***" if SECRET_HDR.match(name) else val) if val else val


def _parse_msg(part, is_response=False):
    part = part.replace("\r\n", "\n").strip("\n")
    if not part.strip():
        return None
    head, sep, body = part.partition("\n\n")
    lines = head.split("\n")
    start = lines[0].strip()
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1); headers[k.strip()] = v.strip()
    if is_response:
        bits = start.split(None, 2)
        return {"status": int(bits[1]) if len(bits) >= 2 and bits[1].isdigit() else 0,
                "headers": headers, "body": (body if sep else "")}
    bits = start.split()
    return {"method": bits[0] if bits else "GET", "path": bits[1] if len(bits) > 1 else "/",
            "version": bits[2] if len(bits) > 2 else "HTTP/1.1", "headers": headers,
            "body": (body if sep else "")}


def parse_transcript(text):
    if "===RESPONSE===" in text:
        req_part, resp_part = text.split("===RESPONSE===", 1)
    else:
        req_part, resp_part = text, None
    return _parse_msg(req_part), (_parse_msg(resp_part, is_response=True) if resp_part is not None else None)


def _resolve_url(req, target):
    if target:
        t = urllib.parse.urlparse(target)
        scheme = t.scheme or "https"; netloc = t.netloc or "127.0.0.1"
        return f"{scheme}://{netloc}{req['path']}"
    host = req["headers"].get("Host") or "127.0.0.1"
    hostonly = host.split(":")[0].lower()
    # localhost / :80 -> http; :443 or public host -> https (default)
    if hostonly in ("127.0.0.1", "localhost", "::1") or host.endswith(":80"):
        scheme = "http"
    else:
        scheme = "https"
    return f"{scheme}://{host}{req['path']}"


def _send(url, method, headers, body, timeout, verify):
    data = body.encode() if body else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=(_CTX if not verify else None)) as r:
            return r.status, {k: v for k, v in r.headers.items()}, r.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k: v for k, v in (e.headers or {}).items()}, e.read(200000).decode("utf-8", "replace")
    except Exception as e:
        return None, {}, str(e)


def _body_sha(body):
    return hashlib.sha256((body or "").encode("utf-8", "replace")).hexdigest()[:16]


def _try_json(body):
    try:
        return json.loads(body)
    except Exception:
        return None


def _json_keys_changed(obs, exp, normalize, path=""):
    """Return list of paths where obs/exp differ, ignoring normalized keys."""
    diffs = []
    norm = {n.lower() for n in normalize}
    if isinstance(obs, dict) and isinstance(exp, dict):
        for k in set(obs) | set(exp):
            if k.lower() in norm:
                continue
            p = f"{path}.{k}"
            if k not in obs: diffs.append(f"{p}: missing in observed")
            elif k not in exp: diffs.append(f"{p}: extra in observed")
            else: diffs += _json_keys_changed(obs[k], exp[k], normalize, p)
    elif isinstance(obs, list) and isinstance(exp, list):
        for i in range(max(len(obs), len(exp))):
            a = obs[i] if i < len(obs) else None; b = exp[i] if i < len(exp) else None
            diffs += _json_keys_changed(a, b, normalize, f"{path}[{i}]")
    else:
        if obs != exp:
            diffs.append(f"{path or '<root>'}: {json.dumps(obs)[:40]!r} != {json.dumps(exp)[:40]!r}")
    return diffs


def diff_responses(obs, exp, normalize):
    """obs/exp are {status, headers, body}. Returns diff dict."""
    norm = {n.lower() for n in normalize}
    status_match = obs["status"] == exp["status"]
    # headers: compare names+values excluding normalized
    oh = {k.lower(): v for k, v in obs["headers"].items() if k.lower() not in norm}
    eh = {k.lower(): v for k, v in exp["headers"].items() if k.lower() not in norm}
    hdr_added = sorted(set(oh) - set(eh)); hdr_removed = sorted(set(eh) - set(oh))
    hdr_changed = sorted(k for k in set(oh) & set(eh) if oh[k] != eh[k])
    # body
    oj, ej = _try_json(obs["body"]), _try_json(exp["body"])
    if oj is not None and ej is not None:
        json_diff = _json_keys_changed(oj, ej, normalize)
        body_same = len(json_diff) == 0
        body_report = {"type": "json", "same": body_same, "field_diffs": json_diff[:15]}
    else:
        body_same = _body_sha(obs["body"]) == _body_sha(exp["body"])
        body_report = {"type": "raw", "same": body_same,
                       "len_obs": len(obs["body"] or ""), "len_exp": len(exp["body"] or ""),
                       "obs_sha": _body_sha(obs["body"]), "exp_sha": _body_sha(exp["body"])}
    reproduced = status_match and body_same
    return {"status_match": status_match,
            "headers": {"added": hdr_added, "removed": hdr_removed, "changed": hdr_changed},
            "body": body_report, "reproduced": reproduced}


def run(transcript_path, target, want_diff, reauth_header, reauth_cookie, normalize, redact, timeout, verify):
    try:
        text = open(transcript_path, encoding="utf-8", errors="replace").read()
    except Exception as e:
        return {"ok": False, "error": f"transcript unreadable: {e}"}
    req, expected = parse_transcript(text)
    if not req:
        return {"ok": False, "error": "transcript has no parseable HTTP request"}

    headers = {"User-Agent": UA}
    for k, v in req["headers"].items():
        if k.lower() in HOP_BY_HOP:
            continue
        headers[k] = v
    authed = any(k.lower() in ("authorization", "cookie") for k in headers)
    if reauth_header and ":" in reauth_header:
        k, v = reauth_header.split(":", 1); headers[k.strip()] = v.strip(); authed = True
    if reauth_cookie:
        headers["Cookie"] = reauth_cookie; authed = True

    url = _resolve_url(req, target)
    status, resp_headers, resp_body = _send(url, req["method"], headers, req["body"], timeout, verify)

    def maybe_mask(d):
        return d if not redact else d  # masking applied to the echoed transcript below

    out = {"ok": True, "target": url, "request": {"method": req["method"], "path": req["path"],
            "host": req["headers"].get("Host", ""), "body_len": len(req["body"] or ""), "authed": authed,
            "headers": ({k: (_mask(k, v) if redact else v) for k, v in headers.items()}
                        if redact else headers)},
           "response_observed": {"status": status,
            "headers": ({k: _mask(k, v) for k, v in resp_headers.items()} if redact else resp_headers),
            "body_len": len(resp_body or ""),
            "body": (resp_body[:300] if redact else resp_body[:300])}}

    if expected is None or not want_diff:
        out["mode"] = "replay-only (no expected response to diff)"
        out["note"] = ("Replayed the captured request; no ===RESPONSE=== section in the transcript (or --diff not set), "
                       "so reproduction is reported as the observed response only. Add a captured response + --diff to score it.")
        return out

    obs = {"status": status, "headers": resp_headers, "body": resp_body}
    d = diff_responses(obs, expected, normalize)
    out["diff"] = d
    # stale-credential heuristic: authed request that flipped to 401/403 where expected was a success
    stale = (authed and expected["status"] < 400 and status in (401, 403))
    if stale:
        out["stale_credential_suspected"] = True
        out["note"] = ("Authed request returned %s where %s was expected — likely a STALE token/cookie, not 'not reproduced'. "
                       "Re-run with --reauth-header/--reauth-cookie (a fresh credential) before concluding the finding no longer reproduces."
                       % (status, expected["status"]))
    else:
        out["note"] = ("reproduced = observed status matches expected AND body matches (JSON structural compare ignoring "
                       "--normalize keys, else sha256). Normalize dynamic fields (Date/Set-Cookie/nonces) to avoid false diffs.")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Raw-HTTP transaction replay + response-diff")
    ap.add_argument("--transcript", required=True, help="captured raw-HTTP transcript file (request [+ ===RESPONSE=== + response])")
    ap.add_argument("--target", help="override scheme://host (default: transcript Host, https)")
    ap.add_argument("--diff", action="store_true", help="diff observed vs the transcript's captured response")
    ap.add_argument("--reauth-header", help="substitute a fresh header, 'Name: value' (fixes stale tokens)")
    ap.add_argument("--reauth-cookie", help="substitute a fresh Cookie value")
    ap.add_argument("--normalize", default="date,set-cookie,etag,last-modified,expires,csrf-token,x-csrf-token",
                    help="comma-separated headers/JSON-keys to ignore in the diff")
    ap.add_argument("--redact", action="store_true", help="mask Authorization/Cookie/Set-Cookie in echoed output")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    print(json.dumps(run(a.transcript, a.target, a.diff, a.reauth_header, a.reauth_cookie,
                         [n.strip() for n in a.normalize.split(",") if n.strip()],
                         a.redact, a.timeout, not a.insecure), indent=2))
