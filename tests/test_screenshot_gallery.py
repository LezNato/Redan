#!/usr/bin/env python
"""test_screenshot_gallery.py — TP + FP-rejection for the screenshot triage tool.

  * TP: a live lab page is captured (HTTP 200 + a real PNG on disk).
  * FP-rejection: a dead host yields an error row and NO screenshot (absence
    recorded as absence — never a blank/fake thumbnail).
  * the HTML gallery is written.

Needs playwright + chromium. CI is stdlib-only/offline, so when the browser is
unavailable the suite SKIPS (exit 0) instead of failing — locally it runs for real.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

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


def main():
    if not have_chromium():
        print("[SKIP] screenshot_gallery — playwright/chromium unavailable (CI is stdlib-only/offline)")
        sys.exit(0)

    srv, base = start_lab()
    out = tempfile.mkdtemp(prefix="shotgal_")
    dead = "http://127.0.0.1:1/"   # nothing listens on port 1 -> connection refused
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(TOOLS, "screenshot_gallery.py"),
             f"{base}/rich", dead, "--out-dir", out, "--timeout", "8000"],
            capture_output=True, text=True, timeout=150)
        try:
            res = json.loads(r.stdout)
        except Exception:
            res = {"_err": r.stdout[-400:] + "\n--STDERR--\n" + r.stderr[-400:]}
        rows = {row.get("url"): row for row in res.get("results", [])}

        live = rows.get(f"{base}/rich", {})
        rec("TP: live page captured (200 + PNG on disk)",
            live.get("status") == 200 and bool(live.get("screenshot"))
            and os.path.exists(os.path.join(out, live.get("screenshot") or "_")),
            str({k: live.get(k) for k in ("status", "screenshot", "error")}))

        d = rows.get(dead, {})
        rec("FP-reject: dead host = error row, NO screenshot",
            d.get("screenshot") is None and bool(d.get("error")), str(d.get("error", ""))[:60])

        rec("gallery.html written", os.path.exists(os.path.join(out, "gallery.html")))
        rec("captured count == 1 (live only)", res.get("captured") == 1, str(res.get("captured")))
    finally:
        srv.shutdown()
        shutil.rmtree(out, ignore_errors=True)

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
