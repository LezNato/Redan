#!/usr/bin/env python
"""second_order.py — second-order injection canary crawl (stdlib; uses the role's session).

Second-order = a payload SANITIZED on input but rendered UNSANITIZED in a DIFFERENT context (an
admin panel, a PDF/CSV export, an email template, search results, a profile-view-as, or concatenated
into a later SQL query). Single-endpoint scanners miss it (they test input+output in the same place).

This injects a unique CANARY into a writeable field (POST via the role's session), then GETs a list
of RENDER-surface URLs and greps for the canary. A hit localizes the second-order sink; re-inject a
real payload there. The canary approach ports directly from the IDOR oracle.

Usage: python second_order.py --engagement E --role A --inject-url <POST> --field 'name=<canary>' \\
        --render-urls <comma-list|@file>   [--canary <marker>] [--insecure]
"""
import sys, os, json, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _authlib as A
from auth_request import load_session
import urllib.parse as _up

def run(engagement, role_name, inject_url, field, render_urls, canary, verify):
    roles = A.load_roles(engagement)
    role, jar, bearer, hdrs = load_session(engagement, roles, role_name)
    if "=" not in field:
        return {"ok": False, "error": "--field must be 'k=v'"}
    k, _ = field.split("=", 1)
    body = _up.urlencode({k: canary}).encode()
    inject = A.request(inject_url, "POST", cookiejar=jar, bearer=bearer,
                       headers={**hdrs, "Content-Type": "application/x-www-form-urlencoded"}, data=body, verify=verify)
    hits = []
    for url in render_urls:
        r = A.request(url, "GET", cookiejar=jar, bearer=bearer, headers=hdrs, verify=verify)
        body_txt = (r.get("body") or b"").decode("utf-8", "replace")
        if canary in body_txt:
            hits.append({"render_url": url, "status": r["status"], "context_snippet": body_txt[max(0, body_txt.find(canary)-40):body_txt.find(canary)+len(canary)+40]})
    return {"ok": True, "engagement": engagement, "role": role_name, "injected_field": k, "canary": canary[:6] + "...",
            "inject_status": inject["status"], "render_urls_checked": len(render_urls),
            "second_order_sinks": hits,
            "findings": [{"id": "second-order-injection-sink", "severity": "high",
                          "detail": f"the canary injected into '{k}' rendered at {h['render_url']} (a DIFFERENT context) — a second-order injection sink. Re-inject a real payload (XSS/SQLi) there (CWE-79/89 second-order).",
                          "render_url": h["render_url"], "snippet": h["context_snippet"]} for h in hits],
            "note": "a hit = the stored value renders elsewhere (second-order). Re-inject the real payload + confirm execution. Needs the role's authenticated session (out-of-tree)."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Second-order injection canary crawl")
    ap.add_argument("--engagement", required=True); ap.add_argument("--role", required=True)
    ap.add_argument("--inject-url", required=True); ap.add_argument("--field", required=True)
    ap.add_argument("--render-urls", required=True, help="comma-list or @file of GET render-surface URLs")
    ap.add_argument("--canary", default="xz2ndOrderCanary9q8r")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    rurls = ([u.strip() for u in open(a.render_urls[1:], encoding="utf-8").read().splitlines() if u.strip()]
             if a.render_urls.startswith("@") else [u.strip() for u in a.render_urls.split(",") if u.strip()])
    print(json.dumps(run(a.engagement, a.role, a.inject_url, a.field, rurls, a.canary, not a.insecure), indent=2))
