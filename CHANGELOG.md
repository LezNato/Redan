# Changelog

All notable changes to Redan are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/). Versions are git-tagged (`vX.Y.Z`).

## [0.4.1] — 2026-06-30

*Report integration for the finding lifecycle.* Additive, backward-compatible.

### Added
- **`render_report.py`** now stamps the stable **`finding_uid`** on every finding and
  shows it as a per-finding **Tracking ID** (md + html) — a cross-engagement reference
  in the deliverable.
- **Retest / remediation delta section** — when `findings.json` carries a `retest` block,
  the report renders a "§ 1b. Retest / remediation delta" (fixed / still-open / new /
  **regressed**) in both `report.md` and the standalone `report.html`.
- **`finding_ledger.py retest --write-into`** (or `--into <findings.json>`) folds the
  retest delta into a findings.json so the renderer picks it up. (`tests/test_render.py`
  covers both the uid stamp and the rendered Retest section.)

## [0.4.0] — 2026-06-30

*Finding lifecycle / retest — the first enterprise-program layer.* New capability,
backward-compatible (a new tool; nothing else changes).

### Added
- **`finding_ledger.py`** — cross-engagement finding lifecycle + retest. Each finding
  gets a STABLE `finding_uid` (fingerprint = `target | CWE | normalized-location`, with
  ids templated out so `/api/orders/1002` ≡ `/api/orders/{id}`) — so the same bug is
  tracked across runs even when the proving object id and the title change. `record`
  upserts an engagement into a gitignored cross-engagement ledger; `retest` diffs a new
  run against it and emits the delta **fixed / still-open / new / regressed**; `status`
  shows the portfolio. Turns one-shot assessments into a security *program*.
  (`tests/test_finding_ledger.py` covers uid-stability + all four retest paths.)
- **73 stdlib modules** (was 72).

## [0.3.3] — 2026-06-30

*Edge-channel routing fixes surfaced by a live re-test against a graylisting target.*
No interface change (the `--proxy` list is backward-compatible with a single value).

### Fixed
- **`waf_detect.py`** — a target that returned **no HTTP response on any probe**
  (timeout/SYN-drop) was misclassified `clean-or-passive` / "reach directly". It was
  actually **per-IP graylisting** the tester — concluding "clean" is a false negative
  that sends you at a wall. The decision is now a pure, unit-tested `classify()` with a
  first-class **`unreachable-or-graylisted`** posture that routes to a fresh egress
  (`proxy_rotate.py`) + the browser channel. (`tests/test_waf_detect.py`.)

### Changed
- **`browser_probe.py` `--proxy`** now accepts a **comma-separated proxy list and fails
  over** — a `proxy_rotate` hit means the proxy reached the edge, not that it can solve
  the PoW in a browser (free proxies are ephemeral). Pass several; it tries each until one
  clears the challenge. Single-value `--proxy` is unchanged.

## [0.3.2] — 2026-06-30

*Guards so the v0.3.1 bug class can't recur — a missing test let it ship.* No
interface change.

### Added
- **`tests/test_render.py`** — the report pipeline had **no** render test, which is
  how the v0.3.0 chokepoint regression shipped unnoticed. Pins the behavior:
  clean→render, advisory-PII→render, secret→refuse (exit 4), legacy/blank
  `evidence_index` row→`finding_schema` error.
- **`doctrine_lint.py` C10** — a render/export redaction **refuse** (`sys.exit(4)`)
  must key off categorized `secret_hits` (`redact.scan`/`scan_file`), never
  `redact_text`'s total count (which includes advisory PII). Regression-locks the
  v0.3.1 render fix across consumers; tested to fire on the old pattern.
- **CONTRIBUTING** — a "Changing a shared primitive" section: grep + update the
  consumers in lockstep, gate on categories not totals, add a test at the seam.

## [0.3.1] — 2026-06-30

*Two bugfixes surfaced while re-verifying a live engagement deliverable.* Patch —
no interface change.

### Fixed
- **`render_report.py`** — v0.3.0 taught `redact_text` to detect PII (emails), but
  the render chokepoint refused-to-render on **any** `redact_text` hit — so it
  blocked on an advisory contact/remediation address and made pre-v0.3.0 reports
  un-renderable, contradicting the qa-gate's "PII is advisory" policy. Now refuses
  on **secret (credential) hits only**; PII is a note and is still neutralized when
  embedded into `report.html`.
- **`finding_schema.py`** — reject `evidence_index` rows missing `file` (e.g. legacy
  `path`/`desc` keys), which render as **blank appendix rows** and drop the
  artifact's embed/caption linkage. Was a human-lens-only catch (a QA-gate BLOCK);
  now deterministic.

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

[0.4.1]: https://github.com/LezNato/Redan/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/LezNato/Redan/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/LezNato/Redan/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/LezNato/Redan/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/LezNato/Redan/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/LezNato/Redan/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/LezNato/Redan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/LezNato/Redan/releases/tag/v0.1.0
