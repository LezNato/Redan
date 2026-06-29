#!/usr/bin/env python
"""test_injection_tools.py — TP + FP-rejection for the 4 rewritten injection tools.

For each tool: it MUST emit a `lead` disposition against the vulnerable endpoint
(true positive) AND MUST NOT against the benign reflector / constant responder
(false-positive rejection — the regression the rewrite fixes). Self-contained:
starts the local lab, runs the real CLIs as subprocesses, asserts the verdict.
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


def run(tool, *args, timeout=150):
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
        # --- nosql_probe: operator-object injection ---
        tp = run("nosql_probe.py", f"{base}/login-nosql-vuln", "--param", "username")
        rec("nosql_probe TP: lead on vulnerable login", disp(tp) == "lead", disp(tp))
        fp = run("nosql_probe.py", f"{base}/login-nosql-safe", "--param", "username")
        rec("nosql_probe FP-reject: no signal on constant login", disp(fp) == "none", disp(fp))

        # --- cmd_inject: computed echo marker + reproduced timing ---
        tp = run("cmd_inject.py", f"{base}/cmd-vuln", "--param", "host")
        rec("cmd_inject TP: lead on shell endpoint", disp(tp) == "lead", disp(tp))
        fp = run("cmd_inject.py", f"{base}/reflect", "--param", "q")
        rec("cmd_inject FP-reject: reflection alone is NOT cmdi", disp(fp) == "none", disp(fp))

        # --- ssti_probe: 7*7 / 8*8 differential, literal consumed ---
        tp = run("ssti_probe.py", f"{base}/ssti-vuln", "--param", "name")
        rec("ssti_probe TP: lead on template engine", disp(tp) == "lead", disp(tp))
        fp = run("ssti_probe.py", f"{base}/reflect", "--param", "q")
        rec("ssti_probe FP-reject: reflected-but-not-evaluated is NOT ssti", disp(fp) == "none", disp(fp))

        # --- xss_scan: executable-context vs non-executing sink ---
        tp = run("xss_scan.py", f"{base}/xss-html", "--param", "q")
        rec("xss_scan TP: lead on raw HTML reflection", disp(tp) == "lead", disp(tp))
        fp1 = run("xss_scan.py", f"{base}/xss-textarea", "--param", "q")
        rec("xss_scan FP-reject: <textarea> sink is non-executing", disp(fp1 := fp1) != "lead", disp(fp1))
        fp2 = run("xss_scan.py", f"{base}/xss-encoded", "--param", "q")
        rec("xss_scan FP-reject: HTML-encoded reflection is non-executing", disp(fp2) != "lead", disp(fp2))
    finally:
        srv.shutdown()

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
