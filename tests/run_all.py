#!/usr/bin/env python
"""run_all.py — run the doctrine self-audit + every tests/test_*.py; aggregate.

Stdlib only, no network: each suite spins up a local 127.0.0.1 lab or tests pure
functions. This is the gate CI runs (see .github/workflows/tests.yml) and the one
command to run locally before a commit:  python tests/run_all.py

  --no-lint   skip the doctrine_lint self-audit (CI runs it as a SEPARATE step so a
              lint failure is distinguishable from a test failure in the red X; the
              default local run still includes it).
"""
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def run(label, argv):
    print(f"\n========== {label} ==========")
    return subprocess.run(argv, cwd=REPO).returncode == 0


def main():
    results = []
    if "--no-lint" not in sys.argv:  # CI runs doctrine_lint as its own step (see tests.yml)
        results.append(("doctrine_lint (self-audit)",
                        run("doctrine_lint", [sys.executable, "tools/checks/doctrine_lint.py"])))
    for t in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
        name = os.path.basename(t)
        results.append((name, run(name, [sys.executable, t])))

    print("\n================ SUMMARY ================")
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    nfail = sum(1 for _, ok in results if not ok)
    print(f"\n{len(results) - nfail}/{len(results)} suites passed")
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
