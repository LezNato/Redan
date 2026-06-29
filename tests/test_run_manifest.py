#!/usr/bin/env python
"""test_run_manifest.py — the engagement audit trail: wrap records a tool run
(enriched from the _result contract), record appends, show summarizes."""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TOOLS = os.path.join(REPO, "tools", "checks")
MANIFEST = os.path.join(TOOLS, "run_manifest.py")
sys.path.insert(0, HERE)
from lab_server import start_lab  # noqa: E402

CHECKS = []


def rec(name, ok, detail=""):
    CHECKS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def main():
    root = tempfile.mkdtemp()
    srv, base = start_lab()
    try:
        # wrap a real tool run; the manifest entry should be enriched from its JSON
        r = subprocess.run([sys.executable, MANIFEST, "wrap", "--engagement", "t", "--root", root,
                            "--", sys.executable, os.path.join(TOOLS, "nosql_probe.py"),
                            f"{base}/login-nosql-safe", "--param", "username"],
                           capture_output=True, text=True, timeout=60)
        rec("wrap passes the tool's stdout through", '"tool": "nosql_probe"' in r.stdout)
        mpath = os.path.join(root, "t", "run_manifest.jsonl")
        rows = [json.loads(l) for l in open(mpath, encoding="utf-8") if l.strip()]
        rec("wrap appended one manifest entry", len(rows) == 1, str(len(rows)))
        e = rows[0]
        rec("entry enriched from _result contract (tool/target/disposition)",
            e.get("tool") == "nosql_probe" and e.get("disposition") == "none" and "target" in e, str(e)[:120])
        rec("entry records exit + timestamp + argv", e.get("exit") == 0 and "ts" in e and "argv" in e)
    finally:
        srv.shutdown()

    # record an explicit entry
    subprocess.run([sys.executable, MANIFEST, "record", "--engagement", "t", "--root", root,
                    "--tool", "burp", "--target", "https://x", "--exit", "0", "--disposition", "lead"],
                   capture_output=True, text=True, timeout=30)
    # show summarizes both
    s = subprocess.run([sys.executable, MANIFEST, "show", "--engagement", "t", "--root", root],
                       capture_output=True, text=True, timeout=30)
    summary = json.loads(s.stdout)
    rec("show counts both runs", summary["runs"] == 2, str(summary.get("runs")))
    rec("show breaks down by tool", summary["by_tool"].get("nosql_probe") == 1 and summary["by_tool"].get("burp") == 1)

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
