# Changelog

All notable changes to Redan are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/). Versions are git-tagged (`vX.Y.Z`).

## [0.3.0] — 2026-06-30

*False-positive discipline: kill confident-but-wrong findings, self-enforce the
doctrine, and gate the kit with tests.* Backward-compatible — additive tooling,
hardening, and tests; no change to the skills/agents interface. **72 stdlib
modules** (68 → 72).

### Added
- **Shared HTTP client** (`tools/checks/_http.py`) — single UA/TLS/proxy
  chokepoint; case-insensitive response headers (`_Headers`). 10 GET/POST probes
  migrated onto it, each verified byte-equivalent to the prior `urllib` path.
- **Canonical tool-output contract** (`tools/checks/_result.py`) — the
  `{tool,target,ok,disposition,signals,verdict,results,note}` shape + validator.
- **Doctrine self-audit** (`tools/checks/doctrine_lint.py`) — deterministic
  C1–C9 scan of the kit's adherence to `.claude/rules/` (no hard CONFIRMED
  verdicts, redact coverage, rule cross-refs, tool refs, agent models,
  finding-schema completeness, repo-passes-own-redact, doc/code drift, stated
  module count). CI-gated.
- **Engagement run-manifest** (`tools/checks/run_manifest.py`) — append-only
  per-engagement audit trail (`run_manifest.jsonl`); wrap/record/show modes.
- **Committed test suite** (`tests/`) + GitHub Actions CI
  (`.github/workflows/tests.yml`) — offline 127.0.0.1 lab, true-positive **and**
  false-positive-rejection per covered injection detector, the authed IDOR
  oracle, and import/compile smoke across all modules. `python tests/run_all.py`.

### Changed
- **False-positive fixes** — `nosql_probe`, `cmd_inject`, `ssti_probe`, and
  `xss_scan` now emit **LEAD, not CONFIRMED** (real operator-object injection /
  computed echo markers / differential template evaluation / non-executing-sink
  detection instead of bare reflection).
- **`redact.py` hardened** — PII detection (email/SSN/Luhn-PAN, advisory unless
  `--strict`) + unlabeled-secret patterns + placeholder/allowlist awareness;
  scans every non-binary file. Credential hits BLOCK.
- **`scope-gate` hardened** — fail-CLOSED on missing/unparseable scope for
  external hosts; broader request-issuing browser-tool gating; IP
  canonicalization (decimal/hex/percent-encoded).
- **Workflow fixes** — richer verdict schema, arbiter verdict now counts, `catch`
  guards, bounded `JSON.stringify`.
- **Reporting fixes** — `export.py` field mapping + redaction chokepoint;
  `render_report.py`/`finding_schema.py` render and validate `derived_from`
  chain provenance.

## [0.2.0] — 2026-06-29

*Edge-egress rotation + new tools + doc polish.* **68 stdlib modules** (62 → 68).

### Added
- `proxy_rotate` — free-proxy egress rotation to beat per-IP graylists;
  `browser_probe --proxy` routes headless Chromium through it.
- `upload_probe` (file-upload abuse), `rate_limit_test` (rate-limit detector),
  `subdomain_enum` (passive multi-source + brute), `soap_probe` (WSDL discovery
  + XXE/SQLi via SOAP), `replay` (raw-HTTP transcript replay + response-diff).
- `jwt_probe` — offline weak-secret crack + active forge (alg:none /
  claim-escalation / RS→HS key-confusion).

### Changed
- 5-pass documentation polish (54 issues fixed); ASCII-normalized workflows.

## [0.1.0] — 2026-06-27

*Initial public release.* **62 stdlib modules**, 8 agents, the
chain-exploitation layer, independent verification, and a QA-gated single-source
reporting pipeline. Proven on real engagements.

[0.3.0]: https://github.com/LezNato/Redan/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/LezNato/Redan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/LezNato/Redan/releases/tag/v0.1.0
