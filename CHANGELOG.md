# Changelog

All notable changes to Redan are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/). Versions are git-tagged (`vX.Y.Z`).

## [0.9.0] — 2026-07-01

*`llm_probe` depth — multi-turn/Crescendo + indirect (data-channel) injection.* Enhances an
existing tool; backward-compatible (still **75 stdlib modules**). Closes the tool's two stated
honest ceilings. Stays **web-app only** (the AI features *of* the web app).

### Added
- **`llm_probe.py` — two new black-box injection batteries**, each keeping the computed-marker LEAD
  discipline (`REDAN`+`17*17`, un-forgeable by a reflector) and each a LEAD (instruction-following
  != a finding until impact):
  - **Multi-turn / Crescendo** (`_probe_multi_turn`) — a gradual escalation across a real `messages[]`
    conversation (benign buildup → elicitation), bypassing a guardrail that inspects only the latest
    turn. `multi_turn_bypassed_singleshot` flags the stronger case where the single-shot override was
    *refused* but the ramp slipped past. Bounded; agnostic body (degrades to a flattened transcript for
    prompt-only endpoints). `--no-multi-turn` to skip.
  - **Indirect / data-channel** (`_probe_indirect`) — the override hidden in a polyglot *secondary*
    field (`context`/`document`/`retrieved`/…) with a benign user prompt; firing = the model executed
    an instruction from the DATA channel (the realistic RAG/agent data-vs-instruction confusion —
    attacker controls a doc, not the prompt). One request; `--no-indirect` to skip.
- **`tests/lab_server.py`** — three endpoints: `/api/chat-guarded` (refuses single-shot, follows a
  multi-turn ramp), `/api/rag` (trusts a retrieved-data field), `/api/rag-safe` (sandboxes the data).
- **`tests/test_llm_probe.py`** — TP for each new signal (multi-turn fires where single-shot is
  refused; indirect fires from the data channel) AND FP-rejection (the defended LLM resists both; the
  data-sandboxing endpoint resists indirect). 16 → **25 checks**.

### Changed
- Docs — `llm_probe` catalog/inventory/dispatch rows expanded; the "honest ceilings (not covered:
  multi-turn + indirect)" line replaced with the one REMAINING ceiling (a true cross-request STORED
  injection needs a known persisted-ingestion vector — the in-request data-channel probe models the
  same confusion without it). New **pitfalls.md** caveats: "multi-turn success is still
  instruction-following — the finding is the guardrail it bypassed" and "indirect injection is
  confirmed only when the data channel is actually attacker-controllable in production" (pairs with
  `second_order.py` for the stored-ingestion half).

## [0.8.0] — 2026-07-01

*The exploiter's exploit-dev lane — a gated, captured surface for bespoke one-off PoCs.*
New agent capability, backward-compatible; **no new module** (the count stays **75 stdlib
modules** — this is doctrine + a template scaffold + a self-audit check, not a tool). Stays
**web-app only**.

### Added
- **Exploit-dev lane** (`engagements/<name>/exploit-dev/`, gitignored) — when a confirmed
  primitive or strong lead needs **bespoke exploit code no fixed probe covers** (a custom
  HMAC/signature gate, an app-specific logic flaw, an odd serialization format, a multi-step
  business-logic chain), the `exploiter` authors + runs a one-off PoC there, captures the
  redacted output + transcript as evidence. The capability was **latent** (the agent already has
  `Bash` + Python); this formalizes it as a disciplined, captured, gated lane. The closest
  architectural edge a fixed-probe kit lacked vs. open-ended agents — now in-scope and on-rails.
  - **Gated two ways, lifts nothing** — off by default; only under `scope.yaml:
    mutation_testing: approved` + an `authorization.md` basis. Enforced by (1) **`mutation-gate.py`**,
    which now hard-denies running any `exploit-dev/<...>.py` unless approved (the PoC *path* is on the
    command line — deterministic, even though the target host + HTTP verbs live inside the .py where the
    host/verb-scanning hooks can't see them), and (2) the **scaffold's `_kit()` self-check**, which
    refuses fail-closed unless approved AND the request host is `in_scope`. Every RoE limit still binds
    (non-destructive, one redacted proof then STOP, no DoS, stay in scope).
  - **The honesty anchor** — a PoC that prints "VULNERABLE" proves nothing (you wrote the
    print). It is `confirmed`/`verified` ONLY after the verifier reproduces the **effect** by a
    method that does NOT re-run the script — replaying its emitted transcript (`replay.py`, the
    cheap default) or independent re-derivation. A PoC reproducible only by its own code stays a
    **lead** (`available`). Falsification is built into the scaffold (a `control()` that must
    independently fail beside the `exploit()`).
- **`engagements/_template/exploit-dev/{_poc_template.py, README.md}`** — the committed scaffold:
  the `control()`/`exploit()` delta structure, fail-closed scope-guarded `_http` helpers (`_kit()`),
  a faithful `replay.py`-format transcript emitter (captures the REAL request sent, parseable by
  `replay.py` — round-trip tested), per-PoC transcript filenames, a redaction reminder, and a
  LEAD-only verdict line (never "confirmed"). `from oob import Collab` is available for blind PoCs.
- **`doctrine_lint.py` C11** — *no real engagement data is git-tracked*: only `engagements/_template/`
  (and `engagements/.gitkeep`) may be committed; evidence, bespoke exploit-dev PoCs, and findings
  must stay gitignored. A target-data leak guard for the blanket `engagements/*` ignore (the lane
  makes target-specific PoCs easy to author). Pure helper `_engagement_leaks()` is unit-tested
  (`tests/test_doctrine_lint.py` check (h)).
- **`tests/test_exploit_dev_lane.py`** — the lane's two failure-critical seams: the scaffold's
  transcript round-trips through `replay.py` (the verifier confirmation path works out of the box),
  its `_kit()` scope guard is fail-closed (in-scope + subdomain allowed; out_of_scope/unknown
  refused), and `mutation-gate.py` flags a real exploit-dev run while exempting the committed template.

### Changed
- **`.claude/hooks/mutation-gate.py`** — now also gates the exploit-dev lane: a path-based hard-deny
  of any `exploit-dev/<...>.py` run unless `mutation_testing: approved` (the committed `_template`
  scaffold is exempt — it carries only a placeholder target, so smoke/compile still run).
- Doctrine wired end-to-end — `.claude/agents/{exploiter,verifier}.md` (the lane + its bespoke-PoC
  reproduction discipline, incl. the replay-must-reach-the-in-scope-target caveat), `evidence-standard.md`
  (Bespoke-PoC reproduction), `pitfalls.md` ("A PoC that prints SUCCESS isn't a finding"),
  `engagement-loop.md` step 4 (the gated exploit-angle substrate), `/pentest` Phase 3.5, and CLAUDE.md
  (chain-exploitation layer + the engagement-path tables). Fixed probe FIRST; the lane only for the
  genuinely uncovered surface.

## [0.7.0] — 2026-07-01

*Bulk screenshot triage.* New recon/triage tool, backward-compatible. 74 → **75 stdlib modules**.

### Added
- **`tools/checks/screenshot_gallery.py`** — bulk web-page screenshot triage
  (gowitness/aquatone-style): renders a list of targets in headless Chromium (reuses
  the `browser_probe` Playwright channel) and writes a single **HTML gallery**
  (thumbnail + HTTP status + page title + final URL per target) for fast visual triage
  of a large web surface — the "which of these hosts is a login page / default install
  / admin panel" pass a status code can't answer. A capture tool (no disposition); a
  DEAD host produces an error row and **NO** screenshot — never a blank/fake thumbnail
  (the recon analogue of the kit's false-positive discipline). Sequential + RoE-gentle
  (one GET render per target); bare hosts try https then http; lazy Playwright import
  (import-smoke safe). Web-app scope.
- **`tests/test_screenshot_gallery.py`** — TP (a live lab page captured: HTTP 200 + a
  real PNG on disk) + FP-rejection (a dead host = error row, NO screenshot) + the
  gallery is written. Browser-dependent, so it SKIPS cleanly when chromium is
  unavailable (CI is stdlib-only/offline) and runs for real locally.

### Changed
- Docs — `screenshot_gallery` added to the `tools/checks/README.md` catalog + the
  CLAUDE.md / README inventories (75-module count). Settled out-of-lane recon
  (repo-secret OSINT, multi-engine host search) remains deliberately unbuilt.

## [0.6.0] — 2026-06-30

*`llm_probe` depth — black-box AI/LLM attack techniques.* Enhances an existing tool;
backward-compatible (still **74 stdlib modules**). Stays **web-app only** — the AI
features *of* the web app.

### Added
- **`llm_probe.py` deepened** with black-box techniques surfaced by a landscape scan
  (garak / PyRIT / promptfoo / Cisco mcp-scanner), each keeping the computed-marker
  LEAD discipline (`REDAN`+`17*17`, un-forgeable by a reflector):
  - **Prompt-injection battery** — several override framings (not one), stop-on-first.
  - **Filter-bypass** — the override Base64/reversed-encoded; firing past a guardrail
    that blocks the plain form = an input-filter bypass (OWASP LLM01).
  - **Tool-abuse / excessive agency** (`--oob`) — the model is told to fetch an OOB
    collaborator URL (reuses `oob.py`); a callback proves the LLM has tool/network reach
    and followed untrusted input = SSRF-via-the-app's-LLM (OWASP LLM06). The strongest
    signal (a real outbound request); still a lead until internal reach is shown.
  - **MCP tool-poisoning** — flags hidden instructions / exfil text inside an exposed
    MCP tool's *description*, beyond bare `tools/list` exposure.
  Honest ceilings stated (deferred): multi-turn / Crescendo + indirect/stored injection.
- **`tests/test_llm_probe.py`** + lab endpoints extended — TP for every new signal
  (Base64 bypass, OOB tool-abuse callback, MCP poisoning) AND FP-rejection (a defended
  LLM is detected but none of injection/leak/tool-abuse fire). 16 checks.

### Changed
- Docs — `llm_probe` catalog/inventory/dispatch rows expanded; new **pitfalls.md** note
  ("LLM tool-abuse callback ≠ confirmed SSRF" — a strong lead that still needs internal
  reach). A landscape scan's out-of-lane suggestions (repo/secret OSINT, multi-engine
  host search) were deliberately NOT built — perimeter/host recon, stated as coverage
  gaps, not web-app testing.

## [0.5.0] — 2026-06-30

*Agnostic AI/LLM web-surface probe.* New capability, backward-compatible (a new
tool; nothing else changes). 73 → **74 stdlib modules**.

### Added
- **`tools/checks/llm_probe.py`** — a vendor/framework-**agnostic** AI/LLM web-surface
  probe (web-app scope only). Agnostic two ways: a **polyglot request body** that sets
  the prompt under every common key at once (messages[].content / prompt / input /
  message / query / text / q / question / content), so whichever key the handler reads
  it gets the prompt; and a **computed detection marker** (asks the model to compute
  `13*13` — the literal `169` is absent from the request, so a plain reflector/echo
  endpoint can't forge it, the same reflection-proof asymmetry `cmd_inject` uses).
  On a detected model it probes **prompt-injection** (an "ignore previous instructions"
  override eliciting an attacker-chosen computed token `REDAN`+`17*17`), **system-prompt
  leak** (an instruction-block heuristic the probe's own prompts are crafted not to
  trip), and **unauthenticated MCP `tools/list`** exposure. Also discovers endpoints
  across an agnostic path list + MCP JSON-RPC. Each signal is a **LEAD** (instruction-
  following ≠ a security finding until impact is shown); an unauthenticated LLM endpoint
  is recorded as **informational**, not a lead (a public chatbot is usually intended).
  Emits the canonical `_result` contract; stdlib + `_http` only; a bounded detector
  (LLM calls cost money), RoE-respecting.
- **`tests/test_llm_probe.py`** + four lab endpoints in `tests/lab_server.py` — TP
  (vulnerable LLM leads on injection + leak; MCP leads on tool exposure) **and**
  FP-rejection (a **defended** LLM is detected but its injection/leak signals do NOT
  fire; a **benign non-LLM reflector** is not detected as an LLM at all — the computed
  marker is un-forgeable). 12 checks, wired into `run_all.py` / CI.

### Changed
- **Docs + dispatch** — `llm_probe` added to the `tools/checks/README.md` catalog, the
  CLAUDE.md / README inventories (74-module count), and the `methodology.md` vuln-class
  dispatch (AI chatbot / chat-completion / MCP → `llm_probe`). New **pitfalls.md** §
  "AI / LLM surface" (the verifier's reference: reachable chatbot ≠ finding; instruction-
  following ≠ injection without impact; computed marker is detection not the vuln; a
  leaked system prompt may be hallucinated; exposed MCP ≠ exploitable tools).

## [0.4.2] — 2026-06-30

*Lifecycle pipeline wiring + web-only scope clarity.* Additive, backward-compatible.

### Added
- **`/pentest-retest` skill** — re-test a previously-assessed site: build the run's
  findings.json, `finding_ledger retest --write-into`, re-render (so the report carries
  the Retest / remediation delta), then QA-gate. Verify-the-fix + regression in one flow.
- **`/pentest-report` auto-records** each engagement into the cross-engagement ledger
  (`finding_ledger record`) so the lifecycle stays current without manual tool calls.

### Changed
- **Scope clarity** — docs state plainly that Redan is **web only** (web applications &
  sites, their APIs, and externally-observable web/cloud exposure); out of scope by
  choice: network / host / Active Directory / mobile / white-box SAST. The retest/
  multi-engagement capability moved from "deferred" to "built" in the status.

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

[0.9.0]: https://github.com/LezNato/Redan/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/LezNato/Redan/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/LezNato/Redan/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/LezNato/Redan/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/LezNato/Redan/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/LezNato/Redan/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/LezNato/Redan/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/LezNato/Redan/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/LezNato/Redan/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/LezNato/Redan/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/LezNato/Redan/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/LezNato/Redan/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/LezNato/Redan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/LezNato/Redan/releases/tag/v0.1.0
