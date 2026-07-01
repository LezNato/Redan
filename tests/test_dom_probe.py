#!/usr/bin/env python
"""test_dom_probe.py — TP + FP-rejection for the client-side (DOM) battery.

Per mode, the tool MUST emit a `lead` on the vulnerable page and `none` on the
benign look-alike:
  --xss          hash -> innerHTML (executes, alert fires)  vs  hash -> textContent
  --postmessage  message handler -> innerHTML, no origin check  vs  origin-checked
  --protopollute `?__proto__[x]=` pollutes Object.prototype   vs  a guarded merge

Needs playwright + chromium. CI is stdlib-only/offline, so the suite SKIPS (exit 0)
when the browser is unavailable; locally it runs for real.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TOOLS = os.path.join(REPO, "tools", "checks")
sys.path.insert(0, HERE)
from lab_server import start_lab  # noqa: E402

CHECKS = []


def rec(name, ok, detail=""):
    CHECKS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def have_chromium():
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        p = sync_playwright().start()
        b = p.chromium.launch(headless=True)
        b.close()
        p.stop()
        return True
    except Exception:
        return False


def run(mode_flag, url, *extra, timeout=150):
    r = subprocess.run([sys.executable, os.path.join(TOOLS, "dom_probe.py"), url, mode_flag, *extra],
                       capture_output=True, text=True, timeout=timeout)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"_err": (r.stdout[-400:] + "\n--STDERR--\n" + r.stderr[-400:])}


def disp(out):
    return (out or {}).get("disposition", out.get("_err", "?") if out else "?")


def main():
    if not have_chromium():
        print("[SKIP] dom_probe — playwright/chromium unavailable (CI is stdlib-only/offline)")
        sys.exit(0)

    srv, base = start_lab()
    try:
        # --- DOM XSS (limit query params to keep it fast; the hash source is always driven) ---
        tp = run("--xss", f"{base}/dom-xss-vuln", "--query-params", "q")
        results = tp.get("results", [])
        rec("dom_probe --xss TP: lead on hash->innerHTML sink", disp(tp) == "lead", disp(tp))
        rec("dom_probe --xss TP: the sink hook actually fired (taint recorded, not just a page alert)",
            any(h.get("sinks") for h in results), str(results))
        rec("dom_probe --xss TP: OUR marker alert() fired (execution observed)",
            any(h.get("executed") for h in results), str(results))
        fp = run("--xss", f"{base}/dom-xss-safe", "--query-params", "q")
        rec("dom_probe --xss FP-reject: hash->textContent does not execute", disp(fp) == "none", disp(fp))
        enc = run("--xss", f"{base}/dom-xss-encoded", "--query-params", "q")
        rec("dom_probe --xss FP-reject: an HTML-ENCODED innerHTML reflection is not a taint",
            disp(enc) == "none", disp(enc))
        ben = run("--xss", f"{base}/dom-alert-benign", "--query-params", "q")
        rec("dom_probe --xss FP-reject: a benign page alert() is not OUR execution",
            disp(ben) == "none", disp(ben))

        # --- postMessage ---
        tp = run("--postmessage", f"{base}/pm-vuln")
        rec("dom_probe --postmessage TP: lead on unguarded handler->innerHTML", disp(tp) == "lead", disp(tp))
        fn = run("--postmessage", f"{base}/pm-logs-origin")
        rec("dom_probe --postmessage TP: a handler that only LOGS e.origin (no gate) is still flagged",
            disp(fn) == "lead", disp(fn))
        fp = run("--postmessage", f"{base}/pm-safe")
        rec("dom_probe --postmessage FP-reject: a REAL e.origin gate on the innerHTML sink",
            disp(fp) == "none", disp(fp))

        # --- client-side prototype pollution ---
        tp = run("--protopollute", f"{base}/pp-vuln")
        rec("dom_probe --protopollute TP: lead on Object.prototype pollution", disp(tp) == "lead", disp(tp))
        fp = run("--protopollute", f"{base}/pp-safe")
        rec("dom_probe --protopollute FP-reject: guarded merge", disp(fp) == "none", disp(fp))
    finally:
        srv.shutdown()

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
