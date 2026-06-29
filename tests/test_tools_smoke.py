#!/usr/bin/env python
"""test_tools_smoke.py — every tool module compiles and imports cleanly.

A fast breakage net across the WHOLE tool surface (not just the tools a given
change touches): py_compile catches syntax errors; a guarded import catches
module-load errors (constants, regex compiles, cross-imports). This is the floor
that makes the incremental _http.py migration safe — a broken tool fails here.
"""
import glob
import os
import py_compile
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CHECKS = os.path.join(REPO, "tools", "checks")

CHECK_RESULTS = []


def rec(name, ok, detail=""):
    CHECK_RESULTS.append(ok)
    if not ok:
        print(f"[FAIL] {name}" + (f" — {detail}" if detail else ""))


def main():
    dirs = [CHECKS, os.path.join(REPO, "tools", "report-render"), os.path.join(REPO, ".claude", "hooks")]
    pyfiles = [f for d in dirs for f in glob.glob(os.path.join(d, "*.py"))]
    print(f"smoke-checking {len(pyfiles)} modules…")

    for f in pyfiles:
        try:
            py_compile.compile(f, doraise=True)
            rec(f"compile {os.path.basename(f)}", True)
        except py_compile.PyCompileError as e:
            rec(f"compile {os.path.basename(f)}", False, str(e).splitlines()[-1])

    # guarded import of every tools/checks module (module-level code only; __main__ is guarded)
    mods = sorted(os.path.splitext(os.path.basename(f))[0] for f in glob.glob(os.path.join(CHECKS, "*.py")))
    code = ("import importlib, sys; sys.path.insert(0, r'%s')\n" % CHECKS +
            "fail=[]\n"
            "for m in %r:\n"
            "    try: importlib.import_module(m)\n"
            "    except Exception as e: fail.append(m+': '+repr(e))\n"
            "print('\\n'.join(fail))\n"
            "sys.exit(1 if fail else 0)" % mods)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    rec("all tools/checks modules import", r.returncode == 0, r.stdout.strip()[:400])

    npass = sum(CHECK_RESULTS)
    print(f"\n{npass}/{len(CHECK_RESULTS)} smoke checks passed ({len(pyfiles)} modules)")
    sys.exit(0 if npass == len(CHECK_RESULTS) else 1)


if __name__ == "__main__":
    main()
