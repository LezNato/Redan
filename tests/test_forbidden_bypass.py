#!/usr/bin/env python
"""test_forbidden_bypass.py — TP + FP-rejection for the 401/403 bypass battery.

  * TP: an admin path gated only by a client-IP allowlist is reached with a spoofed
    X-Forwarded-For: 127.0.0.1 -> a `lead` with an `ip`-family hit.
  * FP-reject: a correctly-locked 403 path holds across every variant -> `none`.
  * a non-403 base (a 200 page) has nothing to bypass -> `none` + an explanatory note.
Stdlib only (no browser); starts the local lab, runs the real CLI.
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


def run(tool, *args, timeout=90):
    r = subprocess.run([sys.executable, os.path.join(TOOLS, tool), *args],
                       capture_output=True, text=True, timeout=timeout)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"_err": (r.stdout[-400:] + "\n--STDERR--\n" + r.stderr[-400:])}


def disp(out):
    return (out or {}).get("disposition", out.get("_err", "?") if out else "?")


def main():
    srv, base = start_lab()
    try:
        tp = run("forbidden_bypass.py", f"{base}/admin-ipwall")
        families = {h.get("family") for h in tp.get("results", [])}
        rec("forbidden_bypass TP: lead on IP-allowlist bypass of a 403", disp(tp) == "lead", disp(tp))
        rec("forbidden_bypass TP: the hit is an `ip`-family spoof", "ip" in families, str(families))

        fp = run("forbidden_bypass.py", f"{base}/admin-locked")
        rec("forbidden_bypass FP-reject: a correctly-locked 403 holds", disp(fp) == "none", disp(fp))

        shell = run("forbidden_bypass.py", f"{base}/shell-admin")
        rec("forbidden_bypass FP-reject: a per-request-VARYING 200 catch-all shell is not a bypass "
            "(length-band calibration, not exact-sha)", disp(shell) == "none", disp(shell))

        nb = run("forbidden_bypass.py", f"{base}/health")
        rec("forbidden_bypass: a non-403 base has nothing to bypass", disp(nb) == "none",
            f"base_status={nb.get('base_status')}")
    finally:
        srv.shutdown()

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
