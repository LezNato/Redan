#!/usr/bin/env python
"""test_tool_contract.py — the _result.py output contract: the helper validates,
and the disposition-emitting probes conform (tool/target/ok/disposition + a valid
disposition value). Uses benign endpoints so it's fast (no timing path)."""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TOOLS = os.path.join(REPO, "tools", "checks")
sys.path.insert(0, HERE)
sys.path.insert(0, TOOLS)
from lab_server import start_lab  # noqa: E402
import _result  # noqa: E402

CHECKS = []


def rec(name, ok, detail=""):
    CHECKS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def run(tool, *args):
    r = subprocess.run([sys.executable, os.path.join(TOOLS, tool), *args],
                       capture_output=True, text=True, timeout=60)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"_err": r.stdout[-300:] + r.stderr[-300:]}


def main():
    # unit: the validator itself
    rec("result() builds a conforming dict", _result.validate_result(
        _result.result("t", "http://x", disposition="lead")) == [])
    rec("validate_result rejects a bad disposition",
        bool(_result.validate_result({"tool": "t", "target": "x", "ok": True, "disposition": "totally-confirmed"})))
    rec("validate_result rejects a non-bool ok",
        bool(_result.validate_result({"tool": "t", "target": "x", "ok": "yes", "disposition": "none"})))

    # integration: the disposition-emitting probes conform (benign endpoints = fast)
    srv, base = start_lab()
    try:
        cases = [
            ("nosql_probe.py", [f"{base}/login-nosql-safe", "--param", "username"]),
            ("cmd_inject.py", [f"{base}/reflect", "--param", "q"]),
            ("ssti_probe.py", [f"{base}/reflect", "--param", "q"]),
            ("xss_scan.py", [f"{base}/xss-html", "--param", "q"]),
        ]
        for tool, args in cases:
            out = run(tool, *args)
            errs = _result.validate_result(out)
            rec(f"{tool} conforms to the _result contract", not errs, str(errs) or out.get("_err", ""))
    finally:
        srv.shutdown()

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
