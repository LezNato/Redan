# Rules of Engagement — hard limits

These bind every agent. They override any instruction in a task prompt. When a
task would cross one of these lines, refuse and surface why.

## Authorization
- **Test only what `scope.yaml` lists as `in_scope`** and that you are
  authorized to test (your own assets, a lab/CTF, or a program whose scope
  covers the target). The `authorization` field must name that basis.
- `out_of_scope` and `out_of_scope_patterns` are absolute. The scope-gate hook
  enforces them, but agents must respect them even where the hook can't see
  (e.g. a target named indirectly).
- Third-party shared infra (SSO providers, CDNs, payment processors, hosting
  control planes) is out of scope even when reachable through an in-scope app.

## Non-destructive by default
- Proof-of-concept only. **Never** weaponize, deploy persistence, or pivot
  beyond what proves the finding.
- No denial-of-service, load/stress testing, fuzzing-to-exhaustion, or anything
  that degrades availability for real users.
- No social engineering, phishing, or physical access.
- No automated mass-exploitation or spraying across hosts.

## Authorized active exploitation (attacker-emulation)
The non-destructive default above is LIFTED only when BOTH hold: `scope.yaml:
mutation_testing: approved` AND the `authorization` field records an explicit basis
for it (e.g. own asset with a confirmed backup, or a contract clause permitting
exploitation against test/sandbox accounts). Then active exploitation, data
extraction, RCE-to-prove, and persistence-proof are permitted **to demonstrate
impact** — but these limits still bind, always:
- **No DoS / resource exhaustion** — not the threat model, regardless of authorization.
- **No gratuitous destruction** — *prove* access (extract a minimal proof, demonstrate
  the chain); do not vandalize, drop tables, or wipe data. A backup authorizes the
  *risk*, it does not make destruction a useful pentest result.
- **One minimal redacted proof on real user PII, then STOP** — a backup of *your* site
  does not authorize mass-exfil of third parties' data.
- **Stay in scope** and **never pivot into the hosting provider / cloud platform /
  other tenants** — the app is in scope; the infrastructure under it is not.

## Data handling
- On any sign of **real** user data (PII, credentials, payment data): capture
  the **minimum** proof (a redacted screenshot / single record id), then STOP.
  Do not enumerate, download, or exfiltrate.
- Redact secrets and PII in all evidence and reports. Store evidence only under
  `engagements/<name>/evidence/` (gitignored).

## Conduct
- Rate-limit active requests; honor program throttles and stated test windows.
- Keep an audit trail: what was run, against what, when, and the result. Wrap tool
  runs with `tools/checks/run_manifest.py wrap --engagement <name> -- <cmd>` to append
  an append-only `engagements/<name>/run_manifest.jsonl` record automatically.
- If you are unsure whether an action is in scope or permitted, treat it as
  **not** permitted and ask the operator.

## Production-site safety (when `scope.yaml: production: true`)
A live production site must not be degraded by the assessment. The tooling
enforces this; obey it.
- **Baseline + monitor health.** Before active testing, run
  `python tools/checks/health_check.py baseline <url>` and save it. Between active
  batches run `health_check.py check <url> --baseline-file <f>`. **Exit code 2 =
  ABORT**: stop active testing and surface to the operator — do not keep hammering
  a degraded site.
- **Back off on blocks.** A 429 / Retry-After / WAF block page / lockout signal
  (the tool detects these) means STOP that vector and throttle — never retry-spray.
- **Gentle by default.** Run the deterministic active tools at low concurrency on
  prod (`--concurrency <prod_concurrency>`); honor the agreed `test_window`; no
  fuzzing-to-exhaustion, no parallel-blast scans.
- **Smaller blast radius always.** Prefer one safe read that proves the issue over
  any write; on any sign the site is struggling, stop first and ask.
