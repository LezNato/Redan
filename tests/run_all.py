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
    """Run a suite; stream its output (nothing lost) AND return it so a failure digest can
    be built. The digest is for the AGENT diagnosing a run — from this output or the CI log
    tail — not for any web dashboard; it pinpoints the failure without scanning every PASS."""
    print(f"\n========== {label} ==========", flush=True)
    r = subprocess.run(argv, cwd=REPO, capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    if r.stderr:
        sys.stdout.write(r.stderr)
    sys.stdout.flush()
    return r.returncode == 0, (r.stdout + r.stderr)


def _fail_lines(text):
    """The diagnostic lines from a failed suite: its [FAIL] lines, else the tail (a crash/
    traceback with no [FAIL] marker). Capped so the digest stays a digest."""
    fails = [ln.rstrip() for ln in text.splitlines() if ln.lstrip().startswith("[FAIL]")]
    if fails:
        return fails[:10]
    tail = [ln.rstrip() for ln in text.splitlines() if ln.strip()][-6:]
    return tail or ["(no output)"]


def main():
    results = []  # (name, ok, output)
    if "--no-lint" not in sys.argv:  # CI runs this same single step WITHOUT --no-lint, so lint runs inline; --no-lint is for a tests-only local run
        ok, text = run("doctrine_lint", [sys.executable, "tools/checks/doctrine_lint.py"])
        results.append(("doctrine_lint (self-audit)", ok, text))
    for t in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
        name = os.path.basename(t)
        ok, text = run(name, [sys.executable, t])
        results.append((name, ok, text))

    print("\n================ SUMMARY ================")
    for name, ok, _ in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    failed = [(n, txt) for n, ok, txt in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} suites passed")

    # Failure digest — the agent working on this repo reads THIS (or the CI log's tail), so
    # re-surface only what broke, in one place, at the end. No scanning the full log.
    if failed:
        print("\n============ FAILURES (diagnose here) ============")
        for name, txt in failed:
            print(f"✗ {name}")
            for ln in _fail_lines(txt):
                print(f"    {ln}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
