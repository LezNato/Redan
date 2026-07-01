# Contributing

Contributions are welcome. A few guidelines:

## Getting Started
1. Fork + clone the repo.
2. Open it in [Claude Code](https://docs.claude.com/en/docs/claude-code/overview) —
   agents, hooks, and skills auto-register from `.claude/`.
3. Read [`CLAUDE.md`](CLAUDE.md) (architecture, conventions) + [`.claude/rules/`](.claude/rules/)
   (the doctrine: tradecraft, evidence standard, methodology, pitfalls, QA gate).

## Code Style
- Match the surrounding code — same naming, structure, comment density.
- Python tools: stdlib-only, argparse, JSON to stdout, `--help` for all.
- HTTP probes: use the shared `_http` client (`from _http import get, post`) and emit
  the `_result` contract shape (`{tool, target, ok, disposition, ...}`) where practical.
- A FINDER/probe emits a **LEAD**, never a hard `CONFIRMED` verdict — `confirmed` is the
  verifier's word. (Enforced by `doctrine_lint.py` C1; opt out only with a justified
  inline `# doctrine-lint: allow CONFIRMED — <reason>` for a paired-control confirmer.)
- No external pip dependencies in the core tools.

## Adding a new tool
1. Add the `.py` file to `tools/checks/` (stdlib-only, argparse, JSON to stdout).
2. Add a row to the table in `tools/checks/README.md`. **(doctrine_lint C8 fails CI if undocumented.)**
3. If it's a vuln-class probe, add a dispatch row to `.claude/rules/methodology.md`.
4. Update the tool count in `CLAUDE.md` and `README.md`. **(doctrine_lint C9 fails CI on drift.)**
5. Add a test to `tests/`: a true-positive AND a false-positive-rejection against a
   `tests/lab_server.py` endpoint (a detector without both halves isn't proven).

## Changing a shared primitive (`redact` / `_http` / `_result` / the report pipeline)
When you change something **other code depends on**, the bug usually lands in a *consumer*
that wasn't updated in lockstep, not in the thing you changed. So:
1. **Grep for the consumers and update them in the same change.** (e.g. hardening `redact`
   to detect PII broke `render_report.py`, which refused-to-render on *any* redact hit
   instead of secret-only — `export.py`, the other consumer, was already correct.)
2. **Use the primitive's categories, not its totals, for a gate.** A refuse/BLOCK keys off
   `redact.scan` `secret_hits`, never `redact_text`'s combined count. **(doctrine_lint C10.)**
3. **Add/extend a test AT THE SEAM** — the behavior the consumer relies on (e.g.
   `tests/test_render.py`: secret→refuse, advisory-PII→render). An un-tested chokepoint is
   how a regression ships silently.

## Testing
- Run **`python tests/run_all.py`** before committing — it runs the doctrine self-audit
  (`doctrine_lint.py` C1–C12) + every `tests/test_*.py`. This is what CI gates
  ([`.github/workflows/tests.yml`](.github/workflows/tests.yml)).
- `redact.py scan` (no credential leaks) and the import/compile smoke run inside it.
- Stage specific files, never `git add -A`.

## Commits
- Clear, conventional-commit-style messages.

## Pull Requests
- One concern per PR. Describe what changed and why.
