#!/usr/bin/env python
"""doctrine_lint.py — does the toolkit obey its OWN rules?

The toolkit's whole thesis is false-positive discipline; this turns that thesis
back on the toolkit's source. A deterministic self-audit of adherence to
.claude/rules/ — the meta-application of "every finding traces to a reproduction".
Run in CI so a regression (a tool reintroducing a hard "CONFIRMED" verdict, a
gutted redactor, a dangling rule cross-reference) FAILS the build.

Checks:
  C1  finder/probe tools must not emit a hard CONFIRMED/VULNERABLE/EXPLOITED
      verdict on a single signal — the disposition vocabulary reserves "confirmed"
      for the post-verifier stage; tools emit LEADs. A tool that legitimately
      confirms via a paired control may opt out with an inline
      `# doctrine-lint: allow <WORD> — <reason>` comment (justified, in source).
  C2  redact.py covers the credential classes the QA gate enumerates (item 6).
  C3  rule cross-references resolve — every *.md a rule cites exists.
  C4  rule tool refs exist — every tools/{checks,report-render}/*.py a rule cites exists.
  C5  agent frontmatter model ids are known/valid.
  C6  finding_schema.REQUIRED covers evidence-standard's mandatory finding fields.
  C7  the repo passes its own redact scan (no unallowlisted secret on the committed surface).
  C8  tool doc-code drift — every tools/checks/*.py is documented in its README, and vice-versa.
  C9  the stated '<N> stdlib modules' count in CLAUDE.md / README.md matches reality.

Usage: python tools/checks/doctrine_lint.py            # exit 1 on any violation
"""
import io, os, re, subprocess, sys, tokenize

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CHECKS = os.path.join(REPO, "tools", "checks")
RULES = os.path.join(REPO, ".claude", "rules")
AGENTS = os.path.join(REPO, ".claude", "agents")

# A HEADLINE verdict: the string begins with a short upper-case label that ENDS in
# the assertion word (e.g. "SSRF CONFIRMED — ...", "XSS CONFIRMED (...)"). This is
# what a single-signal finder must NOT emit. It deliberately does NOT match the word
# mid-sentence in a cautionary note ("...not a basis for CONFIRMED reach").
VERDICT_HEADLINE = re.compile(r"^[A-Z][\w/ &\-]{0,40}?(CONFIRMED|VULNERABLE|EXPLOITED)\b")
_STR_PREFIX = re.compile(r"""^[a-zA-Z]*('''|\"\"\"|'|\")""")


def _rel(path):
    try:
        return os.path.relpath(path, REPO)
    except ValueError:  # different drive (Windows) — fall back to the absolute path
        return path


def _list_py(d):
    return [os.path.join(d, f) for f in sorted(os.listdir(d))
            if f.endswith(".py") and not f.startswith("doctrine_lint")]


def c1_no_hard_confirmed(paths=None):
    """Flag short verdict-style string literals asserting CONFIRMED/VULNERABLE/EXPLOITED."""
    violations = []
    for path in (paths if paths is not None else _list_py(CHECKS)):
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        lines = src.splitlines()
        try:
            toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
        except tokenize.TokenError:
            continue
        for tok in toks:
            if tok.type != tokenize.STRING:
                continue
            val = tok.string
            # skip long strings (docstrings / notes); verdict headlines are short
            if len(val) > 160:
                continue
            inner = _STR_PREFIX.sub("", val).strip()  # drop f/r prefix + opening quote
            m = VERDICT_HEADLINE.match(inner)
            if not m:
                continue
            ln = tok.start[0]
            # an allow directive may sit on the verdict line OR anywhere in the
            # contiguous comment block immediately above it
            allowed = "doctrine-lint: allow" in lines[ln - 1]
            j = ln - 2
            while not allowed and j >= 0 and lines[j].lstrip().startswith("#"):
                if "doctrine-lint: allow" in lines[j]:
                    allowed = True
                j -= 1
            if allowed:
                continue
            word = m.group(1)
            violations.append(f"{_rel(path)}:{ln}: emits hard '{word}' verdict "
                              f"{val.strip()[:60]} — finders must emit a LEAD (or add "
                              f"`# doctrine-lint: allow {word} — <reason>`)")
    return violations


def c2_redact_coverage():
    sys.path.insert(0, CHECKS)
    try:
        import redact
    except Exception as e:
        return [f"redact.py failed to import: {e}"]
    labels = {p[0] for p in redact.P}
    need = {"Authorization/Cookie header": "auth-header", "Set-Cookie": "set-cookie",
            "JWT": "jwt", "api_key/password (kv)": "kv-secret"}
    return [f"redact.py missing coverage for QA-gate class '{cls}' (label '{lbl}')"
            for cls, lbl in need.items() if lbl not in labels]


def _existing_md():
    found = set()
    for d, _, fs in os.walk(REPO):
        if ".git" in d:
            continue
        for f in fs:
            if f.endswith(".md"):
                found.add(f.lower())
    return found


def c3_rule_md_refs():
    existing = _existing_md()
    violations = []
    for f in sorted(os.listdir(RULES)):
        if not f.endswith(".md"):
            continue
        text = open(os.path.join(RULES, f), encoding="utf-8").read()
        for ref in set(re.findall(r"\b([A-Za-z0-9][\w\-]*\.md)\b", text)):
            if ref.lower() not in existing:
                violations.append(f".claude/rules/{f}: references '{ref}' which does not exist")
    return violations


def c4_rule_tool_refs():
    tool_files = {f for f in os.listdir(CHECKS) if f.endswith(".py")}
    # also accept report-render tools
    rr = os.path.join(REPO, "tools", "report-render")
    tool_files |= {f for f in os.listdir(rr) if f.endswith(".py")}
    violations = []
    srcs = [os.path.join(RULES, f) for f in os.listdir(RULES) if f.endswith(".md")]
    for path in srcs:
        text = open(path, encoding="utf-8").read()
        # only check references qualified with tools/checks/ or tools/report-render/
        for ref in set(re.findall(r"tools/(?:checks|report-render)/([\w]+\.py)", text)):
            if ref not in tool_files:
                violations.append(f"{_rel(path)}: references tool '{ref}' which "
                                  f"does not exist under tools/")
    return violations


def c5_agent_models():
    valid = {"sonnet", "opus", "haiku"}
    valid_prefix = ("claude-",)
    violations = []
    for f in sorted(os.listdir(AGENTS)):
        if not f.endswith(".md"):
            continue
        text = open(os.path.join(AGENTS, f), encoding="utf-8").read()
        m = re.search(r"(?m)^model:\s*(\S+)\s*$", text)
        if not m:
            continue  # model is optional (inherits)
        model = m.group(1).strip().strip('"\'')
        if model not in valid and not model.startswith(valid_prefix):
            violations.append(f".claude/agents/{f}: unknown model id '{model}'")
    return violations


def c6_schema_required():
    sys.path.insert(0, CHECKS)
    try:
        import finding_schema
    except Exception as e:
        return [f"finding_schema.py failed to import: {e}"]
    must = {"title", "severity", "cvss_vector", "cwe", "location", "reproduction",
            "evidence", "remediation", "verification"}
    missing = must - set(finding_schema.REQUIRED)
    return [f"finding_schema.REQUIRED missing evidence-standard field '{x}'" for x in sorted(missing)]


def c7_repo_passes_redact():
    """No UNALLOWLISTED, non-placeholder SECRET on the committed surface — redact.py's
    own gate turned back on the repo (the toolkit passes the discipline it preaches).
    PII is advisory and not checked here. Scans tracked + to-be-added files so it works
    pre-commit; skips cleanly if git is unavailable."""
    sys.path.insert(0, CHECKS)
    try:
        import redact
    except Exception as e:
        return [f"redact import failed: {e}"]
    files = []
    for a in (["ls-files"], ["ls-files", "--others", "--exclude-standard"]):
        try:
            files += subprocess.run(["git"] + a, cwd=REPO, capture_output=True,
                                    text=True, timeout=30).stdout.split("\n")
        except Exception:
            return []  # no git -> skip (don't fail the build on environment)
    violations = []
    for rel in sorted({f.strip() for f in files if f.strip()}):
        p = os.path.join(REPO, rel)
        if not os.path.isfile(p) or not redact.is_scannable(p):
            continue
        for h in redact.scan_file(p):
            if h["category"] == "secret":
                violations.append(f"{rel}:{h['line']}: secret-shaped '{h['pattern']}' on the committed "
                                  f"surface — redact it, use a placeholder, or mark `# redact-allow`")
    return violations


def c8_tool_doc_drift():
    """Bidirectional doc-code drift: every tools/checks/*.py is documented in
    tools/checks/README.md, and every tool the README names exists somewhere under
    tools/ (so a new tool can't ship undocumented, nor a doc row outlive its tool)."""
    text = open(os.path.join(CHECKS, "README.md"), encoding="utf-8").read()
    documented = set(re.findall(r"`([\w]+\.py)`", text))
    actual = {f for f in os.listdir(CHECKS) if f.endswith(".py")}
    elsewhere = set()
    for d, _, fs in os.walk(os.path.join(REPO, "tools")):
        elsewhere |= {f for f in fs if f.endswith(".py")}
    violations = [f"tools/checks/{f} is not documented in tools/checks/README.md (doc-code drift)"
                  for f in sorted(actual - documented)]
    violations += [f"tools/checks/README.md names '{f}' but no such tool exists"
                   for f in sorted(documented - actual) if f not in elsewhere]
    return violations


def c9_module_count():
    """A stated '<N> stdlib modules' count in CLAUDE.md / README.md matches reality
    (the count drift that had to be fixed by hand — now mechanical)."""
    actual = len([f for f in os.listdir(CHECKS) if f.endswith(".py")])
    bad = []
    for doc in ("CLAUDE.md", "README.md"):
        text = open(os.path.join(REPO, doc), encoding="utf-8").read()
        for n in re.findall(r"(\d+) stdlib modules", text):
            if int(n) != actual:
                bad.append(f"{doc} says '{n} stdlib modules' but tools/checks/ has {actual}")
    return bad


CHECK_FNS = [
    ("C1 no-hard-CONFIRMED verdicts", c1_no_hard_confirmed),
    ("C2 redact covers QA-gate classes", c2_redact_coverage),
    ("C3 rule .md cross-refs resolve", c3_rule_md_refs),
    ("C4 rule tool refs exist", c4_rule_tool_refs),
    ("C5 agent model ids valid", c5_agent_models),
    ("C6 finding_schema REQUIRED complete", c6_schema_required),
    ("C7 repo passes its own redact scan", c7_repo_passes_redact),
    ("C8 tool doc-code drift", c8_tool_doc_drift),
    ("C9 stated module count is accurate", c9_module_count),
]


def main():
    total = 0
    for name, fn in CHECK_FNS:
        try:
            v = fn()
        except Exception as e:
            v = [f"check raised: {e}"]
        if v:
            total += len(v)
            print(f"[FAIL] {name} ({len(v)})")
            for item in v:
                print(f"    - {item}")
        else:
            print(f"[PASS] {name}")
    print(f"\n{total} doctrine-adherence violation(s)")
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
