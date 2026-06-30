#!/usr/bin/env python
"""test_doctrine_lint.py — the self-audit linter must (a) PASS on the current tree
(regression guard) and (b) actually CATCH a hard-CONFIRMED verdict, while honoring
the inline allow directive."""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
LINT = os.path.join(REPO, "tools", "checks", "doctrine_lint.py")
sys.path.insert(0, os.path.join(REPO, "tools", "checks"))
import doctrine_lint  # noqa: E402

CHECKS = []


def rec(name, ok, detail=""):
    CHECKS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def write(tmp, body):
    p = os.path.join(tmp, "probe_x.py")
    with open(p, "w", encoding="utf-8") as f:
        f.write(body)
    return p


def main():
    # (a) the whole linter passes on the real tree
    r = subprocess.run([sys.executable, LINT], capture_output=True, text=True, timeout=60)
    rec("linter PASSES on current tree", r.returncode == 0, r.stdout[-300:])

    # (b) it CATCHES a single-signal hard verdict
    tmp = tempfile.mkdtemp()
    bad = write(tmp, 'def f():\n    verdict = "SQLI CONFIRMED — single signal"\n    return verdict\n')
    rec("catches a hard CONFIRMED verdict", len(doctrine_lint.c1_no_hard_confirmed([bad])) == 1)

    # (c) it honors the inline allow directive
    ok = write(tmp, 'def f():\n    # doctrine-lint: allow CONFIRMED — paired control proves it\n'
                    '    verdict = "SQLI CONFIRMED — with control"\n    return verdict\n')
    rec("honors the allow directive", len(doctrine_lint.c1_no_hard_confirmed([ok])) == 0)

    # (d) it does NOT flag a cautionary note mid-sentence, or a LEAD verdict
    clean = write(tmp, 'def f():\n    note = "this is not a basis for CONFIRMED reach"\n'
                       '    verdict = "SQLI LEAD — boolean signal"\n    return verdict, note\n')
    rec("ignores mid-sentence note + LEAD verdict", len(doctrine_lint.c1_no_hard_confirmed([clean])) == 0)

    # (e) C10 CATCHES a render/export that refuses on redact_text TOTAL (incl. advisory PII)
    rr_bad = tempfile.mkdtemp()
    with open(os.path.join(rr_bad, "render_x.py"), "w", encoding="utf-8") as f:
        f.write("from redact import redact_text\n"
                "_, hits = redact_text(open('f').read())\n"
                "if hits:\n    print('REFUSING'); sys.exit(4)\n")
    rec("C10 catches refuse-on-redact_text-total", len(doctrine_lint.c10_redaction_refuse_categorized(rr_bad)) == 1)

    # (f) C10 does NOT flag a refuse keyed off categorized secret hits
    rr_ok = tempfile.mkdtemp()
    with open(os.path.join(rr_ok, "render_y.py"), "w", encoding="utf-8") as f:
        f.write("from redact import redact_text, scan_file\n"
                "if [h for h in scan_file('f') if h['category']=='secret']:\n    sys.exit(4)\n")
    rec("C10 ignores categorized-secret refuse", len(doctrine_lint.c10_redaction_refuse_categorized(rr_ok)) == 0)

    # (g) C9 count-claim matcher is phrasing-agnostic — catches "<N> deterministic
    #     tools" / "<N>-tool catalog" / line-split, without false-positiving on
    #     adjacent "<N> <noun>" prose (the README:23/130 drift that bare-phrase missed).
    cc = doctrine_lint._COUNT_CLAIM
    pos = ["75 stdlib modules", "73 deterministic tools", "the 73-tool catalog",
           "the 75\ntools are stdlib", "75-tool catalog"]
    neg = ["8 agents", "5 skills", "OWASP Top 10", "API Top 10", "Python 3.10+",
           "NIST SP 800-115", "2 render tools", "4-cell IDOR", "7-source passive"]
    rec("C9 regex catches all count phrasings", all(cc.search(s) for s in pos),
        str([s for s in pos if not cc.search(s)]))
    rec("C9 regex ignores non-count <N> <noun> prose", not any(cc.search(s) for s in neg),
        str([s for s in neg if cc.search(s)]))

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
