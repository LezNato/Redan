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
- No external pip dependencies in the core tools.

## Adding a new tool
1. Add the `.py` file to `tools/checks/` (stdlib-only, argparse, JSON to stdout).
2. Add a row to the table in `tools/checks/README.md`.
3. If it's a vuln-class probe, add a dispatch row to `.claude/rules/methodology.md`.
4. Update the tool count in `CLAUDE.md` and `README.md`.

## Testing
- Every tool must parse + run `--help` + smoke against an unreachable host without crashing.
- Run `python tools/checks/redact.py scan` before committing (no credential leaks).
- Stage specific files, never `git add -A`.

## Commits
- Clear, conventional-commit-style messages.

## Pull Requests
- One concern per PR. Describe what changed and why.
