#!/usr/bin/env python
"""ssti_probe.py — Server-Side Template Injection tester (Tplmap-style).

Detects SSTI by DIFFERENTIAL evaluation, not a single substring. For each engine
syntax it sends `7*7` (expects 49) AND a control `8*8` (expects 64), and requires:
  * 49 appears for the 7*7 payload AND 64 for the 8*8 payload (both products), and
  * neither 49 nor 64 was already in the benign BASELINE response, and
  * the literal payload was CONSUMED (not reflected) — a real engine renders
    `{{7*7}}` away; an app that merely echoes it is not SSTI.
The old `evaluated AND reflected` gate was backwards (a true engine consumes the
literal) and `'49' in body` alone is ubiquitous-substring noise — both fixed here.

Emits a LEAD, never "confirmed". CWE-1336. See evidence-standard.md / pitfalls.md.

Usage: python ssti_probe.py <url> --param name [--method GET|POST] [--data 'k=__INJECT__']
"""
import argparse, concurrent.futures, json, os, sys, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _http import get, post

# label, wrapper with an EXPR placeholder. Arithmetic-capable engines only (the
# differential needs a computable expression). Engines sharing syntax are grouped.
ENGINES = [
    ("jinja2/twig/pebble", "{{EXPR}}"),
    ("freemarker/mako/jsp", "${EXPR}"),
    ("smarty",             "{EXPR}"),
    ("velocity",           "#set($x=EXPR)$x"),
    ("erb/ejs/asp",        "<%=EXPR%>"),
    ("pug",                "=EXPR"),
    ("thymeleaf",          "[[${EXPR}]]"),
    ("stringtemplate",     "<EXPR>"),
]
CANARY = "redan_ssti_canary"


def fire(url, param, value, method, data_tmpl):
    if method == "POST":
        body = data_tmpl.replace("__INJECT__", urllib.parse.quote(value))
        return post(url, data=body.encode(),
                    headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=15)
    sep = "&" if "?" in url else "?"
    return get(f"{url}{sep}{param}={urllib.parse.quote(value)}", timeout=15)


def probe(url, param, label, wrapper, method, data_tmpl, baseline_text):
    p7 = wrapper.replace("EXPR", "7*7")
    p8 = wrapper.replace("EXPR", "8*8")
    r7 = fire(url, param, p7, method, data_tmpl)
    r8 = fire(url, param, p8, method, data_tmpl)
    if r7.error or r8.error:
        return {"engine": label, "payload": p7, "error": (r7.error or r8.error)}
    b7, b8 = r7.text, r8.text
    eval7 = ("49" in b7) and ("49" not in baseline_text)
    eval8 = ("64" in b8) and ("64" not in baseline_text)
    reflected = (p7 in b7)  # literal NOT consumed -> not real SSTI
    ssti = eval7 and eval8 and not reflected
    return {"engine": label, "payload": p7, "evaluated_7x7": eval7, "evaluated_8x8": eval8,
            "literal_reflected": reflected, "ssti_lead": ssti, "status": r7.status}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--param", required=True)
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    ap.add_argument("--data", default="")
    ap.add_argument("--concurrency", type=int, default=6)
    args = ap.parse_args()
    data_tmpl = args.data or f"{args.param}=__INJECT__"

    # baseline (benign value) — to exclude pages that already contain 49/64
    base = fire(args.url, args.param, CANARY, args.method, data_tmpl)
    baseline_text = "" if base.error else base.text

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futs = [pool.submit(probe, args.url, args.param, lbl, wr, args.method, data_tmpl, baseline_text)
                for lbl, wr in ENGINES]
        for f in concurrent.futures.as_completed(futs):
            results.append(f.result())
    leads = [r for r in results if r.get("ssti_lead")]
    print(json.dumps({
        "tool": "ssti_probe", "target": args.url, "param": args.param, "ok": True, "payloads_tested": len(results),
        "signals": len(leads), "disposition": "lead" if leads else "none",
        "verdict": ("SSTI LEAD — template engine evaluated a differential expression (7*7=49 AND "
                    "8*8=64, literal consumed); verify exploitation") if leads
                   else "no SSTI signal",
        "results": results, "lead_details": leads,
        "note": "A lead requires BOTH products present (not in baseline) and the literal consumed — "
                "a real engine renders the expression away. LEAD only; the verifier confirms RCE/"
                "sandbox-escape exploitability."}, indent=2))


if __name__ == "__main__":
    main()
