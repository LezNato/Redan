#!/usr/bin/env python
"""header_probe.py — pre-auth request-tampering battery (stdlib only).

Four single-request hypothesis-splitters, each with a built-in control (engagement-loop step 3/5):
  host     — X-Forwarded-Host reflection into body/Location (host-header injection)
  crlf     — CRLF injection into a RESPONSE header (response-splitting)
  method   — X-HTTP-Method-Override verb-tunneling (control: same URL without override)
  redirect — off-origin open-redirect via a redirect param (kills same-origin / post-login FP)

ACTIVE (request tampering) — NOT passive recon. A finding is emitted ONLY when the tampered
request differs from the clean control. Positives are LEADS until chained to impact. Through a
JS-challenge WAF these urllib probes are BLIND (pitfalls.md) — re-test positives via the browser.

Usage: python header_probe.py <url> [--probes host,crlf,method,redirect] [--redirect-param redirect_to]
"""
import sys, json, ssl, argparse, urllib.request, urllib.parse, urllib.error

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
_OPENER = urllib.request.build_opener(_NoRedirect)

def _req(url, headers=None, method="GET", timeout=15):
    h = {"User-Agent": UA, "Accept": "text/html,application/json;q=0.9"}
    if headers:
        h.update(headers)
    r = urllib.request.Request(url, headers=h, method=method)
    try:
        with _OPENER.open(r, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, {}, str(e)

def probe_host(url):
    probe = "evil-hostheader-probe.test"
    s, h, b = _req(url, {"X-Forwarded-Host": probe})
    reflected = probe in b
    return {"reflected": reflected, "status": s,
            "finding": {"id": "host-header-injection", "severity": "low",
                        "detail": "X-Forwarded-Host reflected into the response body — a host-header-injection / password-reset-poisoning / cache-poisoning primitive; chain to impact"} if reflected else None}

def probe_crlf(url):
    flag = "X-Probe-Injected-Flag"
    s, h, b = _req(url.rstrip("/") + "/%0d%0a" + flag + ":1")
    got = h.get(flag) or h.get(flag.lower())
    return {"status": s, "injected_header": got,
            "finding": {"id": "crlf-response-splitting", "severity": "medium",
                        "detail": "CRLF in the path was reflected into a RESPONSE header — response-splitting / header injection"} if got else None}

def probe_method(url):
    s_ctrl, _, _ = _req(url, method="POST")
    s_ov, _, _ = _req(url, method="POST", headers={"X-HTTP-Method-Override": "GET"})
    honored = (s_ctrl != s_ov) and (s_ov == 200)
    return {"control_post_status": s_ctrl, "override_status": s_ov, "honored": honored,
            "finding": {"id": "method-override-honored", "severity": "low",
                        "detail": "X-HTTP-Method-Override honored (overrode a blocked verb to 200) — may enable method-based access-control bypass or cache confusion; chain against a gated endpoint"} if honored else None}

def probe_redirect(url, param):
    probe = "https://evil-redirect-probe.test/"
    probe_host = urllib.parse.urlparse(probe).netloc.lower()
    sep = "&" if "?" in url else "?"
    s, h, b = _req(f"{url}{sep}{param}={urllib.parse.quote(probe)}")
    loc = h.get("Location") or h.get("location")
    # off-origin ONLY if the Location's HOST is the probe host — NOT merely if the probe
    # string appears in Location (a same-origin canonical redirect that preserves the query
    # would otherwise false-flag; proven on a WAF'd site's 301-to-apex).
    external = bool(loc) and urllib.parse.urlparse(loc).netloc.lower() == probe_host
    return {"status": s, "location": loc, "external_redirect": external,
            "finding": {"id": "open-redirect", "severity": "medium",
                        "detail": f"off-origin redirect via the '{param}' parameter — phishing / OAuth-redirect-uri-token-theft primitive"} if external else None}

def run(url, probes, redirect_param):
    out = {"target": url, "ok": True, "probes": {}}
    findings = []
    dispatch = {"host": probe_host, "crlf": probe_crlf, "method": probe_method}
    for name, fn in dispatch.items():
        if name in probes:
            r = fn(url); out["probes"][{ "host": "host_header", "crlf": "crlf", "method": "method_override"}[name]] = r
            if r.get("finding"):
                findings.append(r["finding"])
    if "redirect" in probes:
        r = probe_redirect(url, redirect_param); out["probes"]["open_redirect"] = r
        if r.get("finding"):
            findings.append(r["finding"])
    out["findings"] = findings
    out["note"] = "ACTIVE request-tampering probes; positives are LEADS until chained to impact. urllib is blind through a JS-challenge WAF (pitfalls.md) — re-test positives via the browser channel."
    return out

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Pre-auth request-tampering battery")
    ap.add_argument("url")
    ap.add_argument("--probes", default="host,crlf,method,redirect")
    ap.add_argument("--redirect-param", default="redirect_to")
    a = ap.parse_args()
    print(json.dumps(run(a.url, set(a.probes.split(",")), a.redirect_param), indent=2))
