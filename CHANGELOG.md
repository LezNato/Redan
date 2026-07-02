# Changelog

All notable changes to Redan are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/). Versions are git-tagged (`vX.Y.Z`).

## [0.12.3] — 2026-07-02

*QC hardening round 3 — a second adversarial sweep found 35 issues; 22 fixed, 0 regressions from
rounds 1-2.* Patch — no new module, still **78 stdlib modules**; behaviour-compatible.

### Security (hooks + redaction)
- **`scope-gate`**: `read_list` strips an inline `# comment` (a commented in_scope/out_of_scope entry was
  mis-parsed → the denylist silently failed OPEN); the denylist now runs over the UNFILTERED host set so a
  scheme-less out-of-scope host on a file-extension TLD (`.sh`/`.md`/`.zip`) can't hide behind the filename
  heuristic (the false "can never hide a denied host" comment corrected).
- **`mutation-gate`**: gate curl's long `--request <verb>` form (only `-X` was matched).
- **`redact`**: catch `"Authorization": "Basic …"` in indented/quoted JSON (browser-channel / HAR evidence)
  that the `^`-anchored pattern missed; scoped to real auth schemes to avoid benign matches.
- **`export`**: CSV cells are formula-injection-neutralized (CWE-1236) in the client deliverable.

### False-finding / FP reductions
- **`lfi_probe`**: the php-source signal subtracts baseline markers too (a page statically serving base64
  PHP no longer fabricates "source disclosure").
- **`upload_probe`**: the acceptance body-gate uses a narrower reject-phrase set (a `{"error":null}` success
  is no longer misread as a rejection).
- **`waf_bypass`**: a bypass is reported only if the ORIGINAL payload was actually blocked (no-WAF endpoints
  no longer report every variant as a bypass).
- **`csrf_probe`**: CONFIRMED requires a token was ACTUALLY stripped (a named-but-absent `--token-name` no
  longer reaches CONFIRMED).
- **`clickjack_probe`**: a scoped `frame-ancestors *.cdn.example.com` is no longer treated as bare `*`.
- **`auth_request`** (IDOR oracle): confirm requires the bogus-id CONTROL to LACK the canary (canary must be
  object-specific), killing an ambient page-global-canary false confirm.
- **`framework_fingerprint`**: `shell_present` reflects non-200 shell suppression (fixes the self-
  contradictory output the v0.12.2 non-200 change introduced).

### Correctness / consistency
- **`auth_request --endpoints @file`** and **`second_order --render-urls @file`** now READ the file (both
  treated the filename as the literal single entry → silently tested nothing).
- **`js_routes`**: the jQuery `$.ajax` pattern was over-escaped and never matched; **`xss_payloads`** token
  exfil reads `.content||.value`; **`rate_limit_test`** adds 503 to LOCK_STATUS (per its docstring);
  **`finding_ledger`** retest-delta lists iterate sorted (were set-ordered → non-deterministic).
- doc drift: `tests/run_all.py` docstring + CHANGELOG compare-link definitions (0.10.0–0.12.3).

### Deferred (13, recorded with fixes) & reverted (1)
Reverted: an `llm_probe` filter-bypass-labelling tweak (needs a lab fixture + test change to land cleanly).
Deferred: oob interactsh startup-timeout + local-poll lock, tls_check unreachable-vs-cert-invalid,
origin_discover content-correspondence, h2_smuggle reproduce-before-flag, header_probe Location reflection,
render/finding_schema info-count reconciliation, framework selective-403 + xsrf-token attribution,
openapi LEAK_RE scoping, deser_detect body scan, health_check baseline-relative status.

## [0.12.2] — 2026-07-02

*QC hardening round 2 — the 11 deferred findings resolved (10 fixed, 1 declined with rationale).*
Patch — no new module, still **78 stdlib modules**; behaviour-compatible.

### Fixed
- **`csrf_probe`**: "CSRF CONFIRMED" now requires a token was actually located+stripped AND the
  wrong-Origin control was NOT rejected — an Origin/Referer-validated endpoint, or a run where no token
  was found to strip, downgrades to a LEAD (was a false CONFIRMED).
- **`nosql_probe`**: the `$where` timing signal is baseline-relative (not an absolute 2.5s) and is
  re-fired SERIALLY to confirm the delay reproduces (concurrency inflated it → false timing lead).
- **`rate_limit_test`**: throttle body-markers must be payload-INDUCED — a marker already on the
  baseline (e.g. a persistent captcha) no longer reads as an active rate limit.
- **`websocket_probe`**: dropped the "spoofed Authorization" FP (an operator-supplied token → 101 is
  expected); a cross-origin handshake is now a CSWSH precondition gated on ambient cookie auth (medium
  with `--cookie`, else info).
- **`framework_fingerprint`**: a uniform non-200 shell (an edge that 403s/401s every path) is now
  detected by body-match, so it no longer reports 7 mutually-exclusive frameworks as HIGH.
- **`oob.py`**: the interactsh poll uses a daemon reader thread instead of `select()` on a pipe (which
  raises OSError on Windows → a silent false-clean for blind SSRF/XXE).
- **`dns_email`**: NXDOMAIN no longer reports the resolver's own IP as the target's A record; a
  CAA/DNSSEC lookup that could not complete (DoH blocked) is reported "unknown", not a false "missing".
- **`scope-gate`/`settings.json`**: the scope matcher + gating list now cover the claude-in-chrome
  `tabs_create` / `browser_batch` URL-reaching tools.

### Reviewed & declined (a documented trade-off, not a defect)
- **scope-gate FILE_EXT** (sweep finding #23): the denylist is provably NOT bypassed — no `out_of_scope`
  pattern ends in a file extension, and URL/IPv4 targets are always extracted regardless of FILE_EXT;
  only a contrived scheme-less host on a file-extension TLD under `enforce_allowlist` is affected, and
  the naive fix reintroduces the file-name false-positive that once blocked the toolkit's own commands.
  Left as-is by design (see the code comment at scope-gate.py:100-107).

## [0.12.1] — 2026-07-02

*QC hardening — a repo-wide adversarial bug/consistency sweep fixed 29 verified defects.* Patch — no
new module, still **78 stdlib modules**; behaviour-compatible (FP reductions + chokepoint fixes).

A 13-dimension multi-agent QC pass (logic / security / consistency / infra), each finding adversarially
verified and then re-confirmed by hand against the source. 40 findings surfaced; 29 fixed here, 11
deferred with a recorded fix.

### Fixed — false-finding / FP reductions (the kit's cardinal sin)
- **`lfi_probe`**: file/PHP-source markers are subtracted against the baselines — a page that STATICALLY
  renders passwd-format text no longer yields a false "LFI CONFIRMED".
- **`upload_probe`**: acceptance gates on the body (a 2xx carrying a rejection message is not "upload allowed").
- **`param_probe`**: reflection tests the injected sentinel VALUE, not the param NAME (often a common word).
- **`cors_probe`**: wildcard `ACAO:*` + credentials is no longer flagged credentialed-read (browsers reject it).
- **`soap_probe`**: error-based SQLi anchored to real DB-error signatures + downgraded HIGH→medium LEAD.
- **`openapi_probe`**: a 500 counts as divergence only when the operation baseline wasn't already 500.
- **`clickjack_probe`**: `frame-ancestors *` is correctly frameable (was a false negative via a dead var).
- **`origin_discover`**: SAN keep is dot-boundary anchored; "serves site directly" needs a real fingerprint, not bare `<html>`.
- **`waf_bypass`/`xss_scan`/`subdomain_enum`/`host_intel`/`multi_target`**: control-in-variant-set, bare-`<`-in-attr, over-broad `error` substring, dead `" envoy"` token, unstripped-comment target.

### Fixed — security & integrity chokepoints
- **`replay --redact`** now redacts the response body (the ternary had two identical branches).
- **`redact`** gained a Stripe secret-key pattern (`sk_live_`/`rk_live_`/`sk_test_`).
- **`mutation-gate`** catches PowerShell-native HTTP mutations (Invoke-WebRequest/RestMethod) + curl `--header` auth, and gates a cd-first bespoke-PoC run.
- **`scope-gate`** fails CLOSED when `enforce_allowlist:true` but `in_scope` is empty.
- **`xxe_probe`/`soap_probe`** OOB collaborators bind all-interfaces so an external target's callback can land (127.0.0.1 = false-clean for real blind XXE).

### Fixed — infra / correctness
- **`cve_lookup`**: OSV 429/5xx classified transient (retry), not cached as a permanent coverage gap.
- **`h2_smuggle`**: guarded the time-parse against a curl-missing 'ERR' string (was an uncaught crash).
- **`proxy_rotate --insecure`** now applies (CERT_NONE was never wired to the opener).
- **`nuclei_scan`/`sqlmap_run`**: `localhost→127.0.0.1` is host-aware (no longer corrupts `localhost.x`).
- **`render_report`**: info scoreboard count includes `informational[]` (matches `finding_schema`).
- doc/comment drift in `_stealth`, `sri_check`, `tests/run_all.py`.

Deferred (tracked, need design care): CSRF verdict-vs-Origin-check, nosql/rate-limit baseline+re-fire,
websocket rejecting-control, OOB Windows pipe-poll, framework non-200 calibration, dns_email
query-fail-vs-absent, scope-gate FILE_EXT-vs-real-TLD, the claude-in-chrome scope matcher.

## [0.12.0] — 2026-07-02

*flow_map surfaces the business-logic invariants that aren't param-shaped.* Minor — no new module,
still **78 stdlib modules**; backward-compatible output.

`flow_map`'s candidate-invariant classifier was param-name only, so it auto-surfaced the price/qty/
status class of rules but never **separation-of-duties** ("can I approve my own request?") or
**audit immutability** ("can I delete the audit trail?") — those are endpoint/method-level, not param-
level. This adds an endpoint pass so the oracle hands the mapper ~4/5 of the classic fraud questions
instead of ~2/5, still LEAD-ONLY and with no new network behaviour.

### Added
- **`flow_map._endpoint_invariants` — two endpoint-level candidate invariants.**
  **`separation-of-duties`** on an approval-step endpoint (`/…/{id}/approve`, `/approve/{id}`, or a
  step in a discovered flow) → the "approver ≠ creator" two-party control, tested via
  `auth_request --funclevel`. **`append-only`** on an audit/immutable record (`/audit`, `/auditlog`) →
  the "no role may DELETE/UPDATE this" rule, tested via `forbidden_bypass` method-swaps. Pure
  classification over already-crawled data (no extra requests); RoE-neutral.
- The token sets are deliberately **tight** (NOISE-LOW): `APPROVAL_TOKENS` keeps only unambiguous
  two-party verbs (`approve`/`approval`/`signoff`/`countersign`/`ratify`) and excludes self-actor /
  self-consent verbs that FP on high-volume routes (`publish`/`release`/`authorize`/`grant`/`endorse`);
  `AUDIT_TOKENS` is `audit`/`auditlog` only (a real audit-trail is caught by `audit`; bare
  `trail`/`journal`/`changelog` FP on blogs/diaries/docs pages). Each covered case has a true-positive
  **and** a false-positive-rejection test (`test_flow_map.py`; new lab fixtures in `lab_server.py`).

### Changed
- `candidate_invariants` entries now carry a **`basis`** field (`param` \| `endpoint`); existing
  param-level entries are unchanged except for `basis:"param"`, endpoint entries add `method` and a
  null `param`. Backward-compatible — the recon/mapper agent reads the annotated
  `business_process_map.json`, not these raw dicts.

## [0.11.1] — 2026-07-01

*Retest rendering — partial-retest coverage honesty in the report delta.* Patch — no new module;
still **78 stdlib modules**.

### Changed
- **`render_report.py` renders an optional retest `note` + per-item `verified` marker** in the
  "Retest / remediation delta" section (md + html). A partial *verify-the-fix* re-test can now state,
  adjacent to the delta table, which findings were LIVE re-verified vs carried forward — so
  "still open" (a not-remediated lifecycle label) is never misread as an affirmative re-verification
  claim. Backward-compatible (renders only when the `retest` block carries the fields). Prompted by
  the `qa-gate` panel flagging exactly that ambiguity on a real partial re-test.

## [0.11.0] — 2026-07-01

*Business-process oracle — the intended-behavior model black-box logic/authz testing lacks.*
Minor — **78 stdlib modules** (was 77).

An architecture comparison (Redan's epistemic-role ensemble vs a proposed 12-role vuln-class
decomposition) found ~11 of those roles relabel existing Redan capability, but ONE was a genuine
gap: Redan has the business-logic PROBE (`flow_probe`) but nothing that produces the INTENDED-behavior
model it must judge against ("the server accepted quantity=-1" is a finding only if -1 breaks a
DOCUMENTED rule). This ships that oracle — as an artifact + phase, not a new agent.

### Added
- **`flow_map.py` — business-process + expected-authz oracle skeleton.** Deterministic: crawls
  (reuses `crawler`) → multi-step **flows** (register/reset/verify/checkout), an **anonymous access
  matrix** (path → gated/open/redirect + a sensitive heuristic), and **candidate invariants**
  (param-name → the business rule it likely encodes + the test). Emits a PROVISIONAL skeleton the
  recon/mapper agent annotates into `engagements/<name>/business_process_map.json` — the ORACLE the
  `logic`/`access-control` lenses test against and the `verifier` judges "accepted-value ≠ bug / 200 ≠
  unauthorized" against. Fills the black-box/unauthenticated gap (`roles.json` covers the authed side).
  RoE-gentle (bounded crawl + capped anon probe). Structural test (`test_flow_map.py`).
- **`engagements/_template/business_process_map.example.json`** — the annotated oracle shape (flows +
  documented invariants + a role×endpoint expected-allow/deny matrix), scaffolded by `/pentest-init`.

### Changed
- **Methodology Phase 2.5 "Model"** — `recon` runs `flow_map` and annotates the intended-behavior +
  expected-authz oracle for stateful/multi-role apps (skipped *with a scoping note* on a thin API /
  static site — `tradecraft-doctrine.md` §3). New dispatch rows for the business-process oracle and
  the pre-auth **account-lifecycle** surface (signup abuse / email-verification bypass / account
  pre-takeover).
- **Oracle wired into the consumers** — `web-tester` (test each documented invariant + expected-deny
  cell), `auth-tester` (walk the expected-authz matrix), `verifier` (judge accepted-value / 200-not-
  unauthorized against the map), and the `pentest-assess` `logic` + `access-control` lenses. 77 → 78.

## [0.10.0] — 2026-07-01

*Client-side attack surface + unauth authz-bypass — closing the gap-hunt's Tier-1 findings.*
Minor — **77 stdlib modules** (was 75).

### Added
- **`dom_probe.py` — client-side (DOM) battery via Playwright.** The client-side half of the
  flagship classes the urllib probes can't reach (SPAs push these into the browser). `--xss`
  INSTRUMENTS the DOM (hooks innerHTML/outerHTML/document.write/eval/setTimeout/insertAdjacentHTML
  via `add_init_script` BEFORE page scripts) and drives `location.hash`/query sources — a marked
  value reaching a sink UNENCODED is a taint LEAD (an HTML-encoded reflection is not, per the
  encoding-neutralization discipline), and only OUR marker-bearing `alert()` counts as execution
  observed (a benign page alert can't forge the signal). `--postmessage` enumerates `message`
  handlers (wraps `addEventListener` pre-load — listeners are otherwise non-enumerable) and flags
  one reaching a sink with NO `event.origin` GATE — a comparison/allowlist check, not a bare
  `location.origin` reference (WSTG-CLNT-11). `--protopollute` drives `?__proto__[x]=` /
  `constructor[prototype]` carriers and checks `Object.prototype` pollution against a clean
  control (CWE-1321). All LEADs. TP+FP lab tests (`test_dom_probe.py`, browser-skip in stdlib CI).
- **`forbidden_bypass.py` — 401/403 access-control bypass battery** (stdlib). On a forbidden
  resource: path-normalization (`/admin/`, `//admin`, `/%2e/`, `..;/`, case, `.json`), URL-rewrite
  headers (`X-Original-URL`), client-IP-spoof headers (`X-Forwarded-For: 127.0.0.1`), and verb
  swaps (state-changing POST/PUT/PATCH gated behind `--allow-mutation`, RoE) — each controlled vs
  the original deny AND two nonexistent-path samples via a **length-band** calibration (not exact
  bytes), so a nonce'd/CSRF homepage can't fabricate a bypass on every request (`path_probe`'s
  soft-404/WAF-shell discipline, `pitfalls.md`). A differing 2xx is a LEAD, never confirmed
  (WSTG-ATHZ-01, CWE-284/285). TP+FP lab test (`test_forbidden_bypass.py`).

### Changed
- **`auth_request.py --funclevel` no longer grades on status alone** (a latent contradiction of the
  kit's own "200 ≠ unauthorized" doctrine — a soft-deny / login-landing 200 false-flagged as broken
  authz). Redesigned: a hard `funclevel-broken` finding now needs POSITIVE privileged evidence (the
  `--canary` marker present in the low-priv 2xx body, which overrides an incidental deny-word); a
  2xx reach without a canary is a `funclevel-lead` the verifier confirms; an endpoint anon also
  reaches is surfaced as its own `unauth-public` lead (CWE-284); and a dead/unverifiable low-priv
  session yields `inconclusive`, never a clean pass (the liveness gate the IDOR mode already had).
  Broadened the soft-deny blocklist. TP + FP + lead + inconclusive tests (`test_auth_funclevel.py`).
- **`methodology.md` DOM-XSS dispatch corrected** — the reflected-XSS row claimed "DOM-XSS via
  `browser_probe.py`", which only *enumerates* the DOM; it now points at `dom_probe.py --xss`. New
  dispatch rows for DOM-XSS / postMessage / client-side prototype pollution / forbidden-response
  bypass. Both tools wired into `web-tester`, `tools/checks/README.md`, `CLAUDE.md`, and the
  coverage matrix; module count 75 → 77.
- **Pre-release adversarial review + hardening.** A multi-agent review (correctness / FP-FN /
  doctrine / test-adequacy lenses → per-finding verification vs the source) surfaced 21 confirmed
  defects the happy-path tests missed — every one fixed before ship: the length-band calibration
  above, marker-filtered DOM execution, encoding-neutralized taint, origin-GATE (not mere reference)
  detection, the `//admin` variant that was a dead no-op, the mutating-verb RoE gate, and the
  funclevel canary/liveness/public-unauth redesign. The lab now models each FP/FN case so the guards
  are regression-tested, not merely present.

## [0.9.3] — 2026-07-01

*Agent-legible test failures — a failure digest (replacing the dashboard-visual CI split).*
Patch — dev-tooling only; no toolkit change; still **75 stdlib modules**.

### Changed
- **`run_all.py` prints a `FAILURES (diagnose here)` digest** on any failed run — it re-surfaces
  only the failing suite(s) + their `[FAIL]` lines (or a crash tail) in one block at the end. The
  agent working on the repo diagnoses from the run's own output (or the CI log tail), so the failure
  is pinpointed without scanning every `[PASS]`. Serves the actual diagnostic path, not a web view.
- **CI (`tests.yml`) reverts to a single step** (`python tests/run_all.py`). The v0.9.2 two-step
  split optimized GitHub's visual report — which the working agent never reads; the in-output digest
  supersedes it. `run_all.py --no-lint` remains for a tests-only local run.

## [0.9.2] — 2026-07-01

*CI clarity — the doctrine self-audit runs as its own step.* Patch — no toolkit change; still
**75 stdlib modules**.

### Changed
- **CI (`tests.yml`) now runs the doctrine self-audit (`doctrine_lint` C1–C12) and the test suite
  as SEPARATE steps**, so a red check is self-explanatory — lint/doc drift vs an actual test
  failure — instead of both hiding behind one job. `run_all.py` gains `--no-lint` (CI runs the lint
  as its own step; the default local `python tests/run_all.py` is unchanged and still includes it).

## [0.9.1] — 2026-07-01

*CI-green fix + v0.9.0 coherence-audit stragglers.* Patch — no interface change; still **75
stdlib modules**.

### Fixed
- **CI had been RED since v0.5.0** — `doctrine_lint` **C3** (rule .md cross-refs) walked the whole
  tree for `.md` files, including the **gitignored `engagements/<name>/report.md`** artifacts present
  on a dev box. So a rule's reference to the generated `report.md` resolved locally but **failed on a
  clean CI checkout** (no engagement folders) → `run_all` failed every push, while local runs passed.
  C3 now resolves refs against **committed files only** — `_existing_md()` prunes the engagement dirs
  (only `_template` survives) and `report.md` is allowlisted as a generated artifact. **Local now
  matches CI.** (Surfaced by the operator noticing the red tag checks; the local-masks-CI class is the
  exact discipline gap the kit exists to close.)
- **v0.9.0 coherence-audit stragglers** (a 5-lens repo audit): a hardcoded real engagement slug
  removed from `run_manifest.py` + a test fixture (now `<name>`/fictional); a stale `doctrine_lint`
  range `C1–C10` corrected to **C1–C12** in `CLAUDE.md` / `CONTRIBUTING.md` / `tests/README.md`; a
  stale `(76)` module count dropped from `tests/README.md` (the smoke test prints the real count).

### Added
- **`doctrine_lint` C12** — no COMMITTED file may hardcode a concrete engagement slug
  (`engagements/<slug>/` or `--engagement <slug>`): a real-target-name leak guard (the
  public-release scrub discipline), turning the audit's manual catch into a mechanical gate.
  Kebab-lowercase-only with a unit-tested pure helper (`tests/test_doctrine_lint.py` check (i));
  the check's own source + fixtures are exempt. (12 checks now gate the kit.)

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

[0.12.3]: https://github.com/LezNato/Redan/compare/v0.12.2...v0.12.3
[0.12.2]: https://github.com/LezNato/Redan/compare/v0.12.1...v0.12.2
[0.12.1]: https://github.com/LezNato/Redan/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/LezNato/Redan/compare/v0.11.1...v0.12.0
[0.11.1]: https://github.com/LezNato/Redan/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/LezNato/Redan/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/LezNato/Redan/compare/v0.9.3...v0.10.0
[0.9.3]: https://github.com/LezNato/Redan/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/LezNato/Redan/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/LezNato/Redan/compare/v0.9.0...v0.9.1
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
