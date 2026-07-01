# Redan — a pentest agent ensemble

A Claude Code-native toolkit for **authorized** penetration testing of **web
applications and sites** — their APIs and externally-observable web/cloud exposure.
That is Redan's entire scope: **web only** — NOT network, host, Active Directory,
mobile, or white-box SAST (out of scope by choice). Built on an ensemble pattern —
many specialty agents + a core evidence discipline
("every claim traces to an evidence row" → here: **every finding traces to a
reproduction**).

Engagement posture: **own assets / bug-bounty + CTF/lab**, aiming for
a **serious, professional, client-deliverable** kit viable for any client. The
methodology maps to recognized standards (OWASP WSTG/ASVS, OWASP API Top 10,
PTES, NIST SP 800-115, CWE/CVSS, MITRE ATT&CK, optional PCI/SOC2/ISO mapping).
See Current state below for what's built vs deferred.

## How it works

```
scope.yaml ─► /pentest ─► recon · web-tester · auth-tester · cloud-iam ─► verifier ─► exploiter ─► reporter ─► qa-auditor ─► report.md
  (gate)                   (sonnet finders, parallel)        (opus,      (opus,        (writes     (opus,        (deliverable)
                                                              refute)     chains)       the file)   PASS/BLOCK)
```

- **Specialty agents** live in `.claude/agents/`: `recon`, `web-tester`,
  `cloud-iam`, `auth-tester` (finders) → `verifier` → `exploiter` → `reporter` → `qa-auditor`. The
  orchestrator fans the finders out in parallel, gates everything through the
  independent `verifier`, then the `qa-auditor` gates the written report before
  it's deliverable.
- **The ensemble's value is role diversity + independent checking**, not just
  more instances. A finder proposes; independent verifier passes try to *refute*;
  the QA gate refuses to ship a report that doesn't meet the bar.
- **Mixed-model by design:** mechanical finders + reporter on `sonnet`;
  judgment-heavy `verifier` + `exploiter` + `qa-auditor` on `opus` (set per-agent in
  frontmatter). The value of a bigger model is on verify/QA, not recon.
- **Skills:** `/pentest-init <slug>` bootstraps an engagement (authorization +
  scope); `/pentest <target>` runs the methodology; `/pentest-report` (re)builds
  the deliverable; `/pentest-retest` diffs a re-test of a previously-tested site
  against the cross-engagement ledger (fixed / still-open / new / regressed delta);
  `/pentest-qa` runs the pre-delivery QA gate. (Invoke via the Skill tool.)

## The gate — `scope.yaml`

The single source of authorization. Fill it in before every engagement:
`in_scope` (what you may test), `out_of_scope` (+ patterns; hard-denied),
`rules_of_engagement`, and `enforce_allowlist`.

**Per-engagement model:** each engagement keeps its durable record in
`engagements/<slug>/{scope.yaml, authorization.md}` (`/pentest-init` scaffolds
it; `authorization.md` is the client intake — basis, signed-doc ref, NDA,
contacts, RoE, sign-off). The repo-root `scope.yaml` is the **active copy** the
hook + agents read — switch engagements with `cp engagements/<slug>/scope.yaml
scope.yaml`. For client work, **`authorization.md` gates the engagement** just as
the hook gates the tools: no active testing until a signed basis is recorded.

`.claude/hooks/scope-gate.py` is a **PreToolUse** hook that hard-denies active
tool calls (Bash / PowerShell / WebFetch / *navigate) reaching an out_of_scope
host. `.claude/hooks/session-start.sh` prints the active scope each session.

> **The hook is a guardrail, not a sandbox.** It scans tool inputs for hosts and
> blocks obvious out-of-scope reach. The real authorization control is *you only
> testing targets you're permitted to test*. The agents are also instructed to
> respect scope where the hook can't see. Don't route around a denial — fix
> `scope.yaml` if it's wrong.

## Key rules (`.claude/rules/`)

Layered by altitude — doctrine (how to test) → loop (how to chase one lead) →
pipeline → hard limits → bar:

1. `tradecraft-doctrine.md` — discipline rules for HOW to test: tag every claim
   (confirmed/refuted/lead), don't guess from a banner, verify with an
   *independent* method, never write "confirmed" before you observed it,
   reproduce through WAF/cache/LB noise, report hygiene. The discipline that
   keeps false positives out.
2. `engagement-loop.md` — the per-lead inner loop: pick lead → audit prior art →
   cheap probe → sharpen → falsification battery → reproduce → independent
   verify → honest close. Runs *inside* methodology phases 3–4, automatable by
   the agent ensemble.
3. `methodology.md` — the macro phase playbook + orchestration notes, **standard
   coverage** (WSTG/ASVS/PTES/NIST/CWE/CVSS/ATT&CK + compliance), and the
   **vuln-class dispatch** (symptom → suspect class → first probe).
4. `pitfalls.md` — the **false-positive catalog**: concrete recurring traps
   (reflected≠XSS, self-XSS, version-banner≠vuln, wildcard-CORS, SSRF callback≠
   reach, missing-header≠High…) with the "confirm or kill" probe for each. The
   `verifier`'s reference.
5. `rules-of-engagement.md` — hard limits (non-destructive, no DoS, no third-
   party infra, minimum-proof data handling). Overrides any task prompt.
6. `evidence-standard.md` — **finding vs lead**, the canonical **disposition
   vocabulary** (confirmed/informational/lead/refuted/duplicate/out-of-scope),
   and **severity-scoring discipline**. The trust anchor.
7. `qa-gate.md` — the **pre-delivery QA gate**: deliverable integrity (report
   actually written), finding completeness, severity discipline, CVE
   corroboration, redaction, coverage honesty, RoE. Run by `qa-auditor` /
   `/pentest-qa`; a report isn't final until it returns PASS.

## Where things go

| Thing | Path |
|---|---|
| Authorization gate | `scope.yaml` |
| Agents | `.claude/agents/*.md` |
| Orchestration skills | `.claude/skills/{pentest-init,pentest,pentest-report,pentest-retest,pentest-qa}/SKILL.md` |
| Reusable workflows | `.claude/workflows/{pentest-assess,qa-gate,plugin_cve_research,toolkit-consistency-audit}.js` — named, parameterized multi-agent workflows run by name: `Workflow({name:'pentest-assess', args:{target,engagement}})` (parallel vuln-class finders → opus verify), `Workflow({name:'qa-gate', args:{engagement}})` (5-lens pre-delivery audit → PASS/BLOCK), and `Workflow({name:'plugin_cve_research', args:{plugins:[{slug,name,version},...]}})` (systematic CVE research across NVD/Wordfence/Patchstack/WPScan for a plugin inventory — fills the OSV WordPress-coverage gap), and `Workflow({name:'toolkit-consistency-audit'})` (repo-wide consistency/drift audit — no engagement hardcoding, stale refs, doc-code drift). The committed, generalizable patterns; target-specific runs stay session-transient. |
| Engagement template | `engagements/_template/{authorization.md,scope.yaml,leads.md,evidence/,exploit-dev/,roles.example.json,README.md}` (copied by `/pentest-init`; `exploit-dev/` = the gated bespoke-PoC scaffold) |
| Hooks | `.claude/hooks/{scope-gate.py,mutation-gate.py,session-start.sh}` (scope-gate = host allow/deny, **fail-CLOSED on missing scope for external hosts**, gates the request-issuing browser tools; mutation-gate = auth testing read-only by default) |
| Rules | `.claude/rules/*.md` |
| Tests / CI | `tests/{lab_server.py,test_*.py,run_all.py,README.md}` — offline 127.0.0.1 lab, **TP + FP-rejection per covered injection detector + the IDOR oracle** (plus import/compile smoke across all modules); `tools/checks/doctrine_lint.py` = deterministic self-audit of kit-vs-rules adherence. `python tests/run_all.py`; CI: `.github/workflows/tests.yml`. |
| Deterministic checks | `tools/checks/{http_headers,tls_check,dns_email,wp_fingerprint,path_probe,port_scan,host_intel,wayback_recon}.py` + `recon_sweep.py` (runs them all concurrently; **host_intel** = passive Shodan InternetDB host-IP enrichment, **wayback_recon** = Wayback CDX historical surface — both passive recon multipliers wired into the sweep). Repeatable JSON the finder agents call; **core-scaled** (`_concurrency.py` — threads fan to ~cores×4, override `--concurrency`). See `tools/checks/README.md`. |
| Integrity/auth tooling | `tools/checks/{redact,finding_schema,auth_login,auth_request,_authlib,doctrine_lint}.py` — credential **+ PII** redactor/scanner (secret hits BLOCK, PII advisory unless `--strict`; scans all non-binary files; placeholder/allowlist aware), **findings.json validator** (band/count/field/enum/dangling-evidence + `derived_from` chain-provenance), **doctrine self-audit** (kit-vs-`.claude/rules/` adherence, CI-gated), + authenticated-session testing (read-only default, **json/REST login**, canary 4-cell IDOR oracle; **E2E-validated**). Credentials OUT OF TREE under `$PENTEST_AUTH_HOME`, never the repo. |
| Depth tooling | `tools/checks/cve_lookup.py` (known-CVE via OSV.dev, no key) + `nuclei_scan.py` (wraps **nuclei** — thousands of deterministic templates; binary via `tools/external/bootstrap.py`, gitignored) + `sqlmap_run.py` (wraps **sqlmap** — confirms SQLi + DBMS, no data dump) + `fuzzer.py` (content-discovery SPA-calibrated + param leads, core-scaled). External tools resolve `127.0.0.1` not `localhost` (wrappers normalize). |
| Production safety | `tools/checks/health_check.py` — baseline a LIVE target, check between active batches, **exit 2 = ABORT** on degrade (5xx/latency/unreachable) or WAF-block/rate-limit. Gated by `scope.yaml: production: true` (+ `prod_concurrency`, `health_latency_factor`); enforced via `rules-of-engagement.md` + `/pentest`. |
| Coverage-depth + scale | `tools/checks/{crawler,js_secrets,graphql_probe,xxe_probe,deser_detect,smuggle_probe,sri_check,header_probe,cors_probe,jwt_probe,multi_target}.py` — same-origin spider (forms/params/JS-endpoints); JS-bundle secret scan; **sri_check** (third-party-JS Subresource-Integrity / supply-chain — missing-SRI + no-CSP + cookie-reading-script exposure); **header_probe** (host-header / CRLF / method-override / open-redirect battery, each with a control); **cors_probe** (reflected-Origin + Allow-Credentials CORS, CWE-942); **jwt_probe** (JWT analyzer + offline weak-secret crack + active forge — alg:none / claim-escalation / RS→HS key-confusion, each paired with a wrong-sig control); GraphQL introspection; XXE battery + built-in OOB collaborator; deserialization-sink + request-smuggling detection (lead-only, honest ceilings); and a multi-target deterministic triage sweep for enterprise scope. Mostly core-scaled — the recon/discovery tools fan to ~cores×4 via `_concurrency.py`; the param-driven probes use a fixed default (override with `--concurrency`). Hard-class tools flag leads for the verifier. (header_probe/sri_check are ACTIVE — not in recon_sweep; web-tester runs them. The param-driven probes cmd_inject/ssti_probe/nosql_probe/xss_scan are likewise ACTIVE and web-tester-run; urllib is blind through a JS-challenge WAF — re-test positives via the browser.) |
| Edge / WAF + bypass recon | `tools/checks/waf_detect.py` — **run FIRST** against an edge-protected target: detects a JS proof-of-work challenge (Imunify360/Cloudflare-class) and routes the testing **channel** (`js-challenge` ⇒ urllib/curl tools are blind → use the **browser agents**, which solve the challenge like a real attacker's headless Chrome). `origin_discover.py` — WAF-bypass recon (find a directly-reachable origin IP = a finding). See `pitfalls.md` "WAF/challenge shell" + `/pentest` recon routing. |
| Report renderer | `tools/report-render/{render_report.py,export.py,report.css,report-light.css,README.md}` — **findings.json (single source) → report.md + report.html (dark)** via `--all` (dark is the default; light/print theme opt-in via `--theme light`; dark survives PDF via a `@media print` block). **report.html is a STANDALONE deliverable**: CSS inlined **and the referenced evidence embedded inline** (text in collapsible `<details>`, screenshots as base64) so a client with only that file has the full evidence; per-finding bullets link to the appendix block; embedded text is redaction-neutralized on the way in (the render-time chokepoint); oversized artifacts truncated/noted; `--no-embed-evidence` opts out. **Standards-aligned:** per-finding `owasp`/`wstg`/`attack` tags + engagement `asvs_level`/`coverage[]`/`limitations[]`/`compliance` render as report **§4 "Standards coverage & limitations"** (WSTG/ASVS/API coverage matrix). **`export.py` → SARIF 2.1.0 / Jira-CSV / DefectDojo** for vuln-mgmt ingestion (redaction chokepoint). Dark-glass visual treatment, re-keyed to pentest severity. |
| Per-engagement files | `engagements/<name>/{authorization.md,scope.yaml,evidence/,exploit-dev/,leads.md,findings.json,report.md,report.html,report-light.html,report-light.pdf}` — `report.*` GENERATED from `findings.json` (never hand-edit); `exploit-dev/` = gated bespoke-PoC scratch (gitignored, exploiter-only) |

`engagements/` holds real target data and is **gitignored** except the template.

## Conventions

- Windows dev box, PowerShell 7 (pwsh) primary; Bash tool available for POSIX.
- Hooks: bash + python (no PyYAML — `scope.yaml` uses a flat, line-parseable
  subset on purpose).
- Is a git repo. The `.gitignore` keeps evidence,
  secrets, and `.env`/`.dev.vars` out of history. Stage specific files, never
  `git add -A`.

## Current state

A comprehensive web-only black-box pentest ensemble: **75 stdlib modules**, **8 agents**, a
**chain-exploitation layer**, edge-egress rotation (proxy + browser channel for
WAF'd/graylisted targets), independent verification, and a QA-gated single-source
reporting pipeline. Proven on real engagements (including a WAF'd WordPress site and a React/ASP.NET SPA) +
validated on a deliberately-vulnerable lab. A committed **`tests/`** suite (offline
127.0.0.1 lab, TP **+** FP-rejection per covered injection detector + the authed IDOR
oracle, plus import/compile smoke across all modules) and a deterministic **doctrine
self-audit** (`tools/checks/doctrine_lint.py`) gate the kit in CI
(`.github/workflows/tests.yml`) against drift from its own discipline.

### Tooling (`tools/checks/` (75 stdlib modules) + `tools/report-render/`)
**Recon**: `http_headers`, `tls_check`, `dns_email` (+CAA/DNSSEC), `wp_fingerprint`, `path_probe`,
`port_scan`, `recon_sweep` (concurrent), `host_intel` (Shodan passive), `wayback_recon` (CDX), `subdomain_enum` (subfinder-style multi-source passive + wordlist brute), `proxy_rotate` (free-proxy egress rotation when an edge graylists your IP),
`waf_detect` (JS-challenge routing), `origin_discover`, `multi_target`, `health_check` (prod safety),
`framework_fingerprint` (active server-framework ID — whatweb-style, beyond the `Server:` banner),
`screenshot_gallery` (bulk headless-Chromium screenshot triage → HTML gallery; dead host = no shot, not a blank).
**Active testing**: `fuzzer`, `crawler`, `js_secrets`, `js_routes` (deep JS), `sri_check`
(supply-chain), `header_probe` (host-header/CRLF/method/redirect), `cors_probe` (CWE-942),
`jwt_probe` (analyzer + offline crack + active forge), `clickjack_probe`, `waf_bypass` (variant battery), `websocket_probe`
(stateful), `race_probe` (TOCTOU), `proto_pollute` (SSPP), `cache_probe` (deception/poisoning),
`second_order` (canary crawl), `takeover_probe` (subdomain), `graphql_probe` + `graphql_adv`
(depth/batch/suggestion), `xxe_probe` (+OOB), `soap_probe` (WSDL discovery + XXE + SQLi via SOAP), `deser_detect`, `smuggle_probe` (H1) + `h2_smuggle`
(H2/h2c), `flow_probe` (business logic), `upload_probe` (file upload abuse — control + bypass battery,
acceptance≠execution), `rate_limit_test` (rate-limit / brute-protection DETECTOR, API4), `cve_lookup` (OSV + coverage_gap), `nuclei_scan` (thousands of
templates), `sqlmap_run`, `param_probe` (param discovery), `cmd_inject` (command injection),
`ssti_probe` (template injection), `nosql_probe` (NoSQL injection), `xss_scan` (XSS
reflection/context) + `xss_payloads` (OOB-exfil proof),
`browser_probe` (Playwright SPA/WAF channel), `lfi_probe` (file inclusion / source disclosure),
`ssrf_probe` (SSRF ladder via OOB), `csp_probe` (CSP bypass analysis), `csrf_probe` (CSRF enforcement),
`oauth_probe` (OAuth grant-flow misconfig), `openapi_probe` (spec-driven API fuzzing),
`llm_probe` (agnostic AI/LLM surface — endpoint/MCP discovery + a computed-marker injection **battery** with encoded **filter-bypass**, **multi-turn/Crescendo** escalation, **indirect/data-channel** injection, **tool-abuse/excessive-agency** via OOB callback, system-prompt-leak, and MCP **tool-poisoning**).
**Authenticated testing** (read-only default, E2E-validated): `auth_login` (form/json/token),
`auth_request` (IDOR canary 4-cell + funclevel + massassign), `_authlib`, `oob.py` (collaborator).
**Integrity/reporting**: `redact` (credential **+ PII** redactor; secret hits BLOCK, PII advisory unless `--strict`; scans every non-binary file incl. `.env`/`.pem`), `finding_schema` (dangling-evidence + `derived_from` chain-provenance + blank/legacy `evidence_index`-row catch), `finding_ledger` (**cross-engagement lifecycle/retest** — stable `finding_uid` fingerprint → fixed/still-open/new/regressed delta; the security-program layer), `replay` (raw-HTTP transcript replay + response-diff — verifier exact-byte reproduction of browser-channel/complex flows; stale-credential-aware), `render_report`
(standalone HTML + logo; renders chain `derived_from`, the stable `finding_uid` per finding, and a **Retest / remediation delta** section when `findings.json` carries a `retest` block from `finding_ledger`), `export` (SARIF/Jira/DefectDojo — canonical `description`/`reproduction`, redaction via `redact`), `doctrine_lint` (deterministic self-audit of the kit's adherence to `.claude/rules/` — C1–C12), `run_manifest` (append-only per-engagement audit trail — wrap/record/show), `_http` (shared HTTP client — single UA/TLS/proxy chokepoint), `_result` (canonical tool-output contract + validator), `_concurrency`, `_stealth` (UA pool + jitter + proxy — wired via `_http`), `_result_cache` (TTL result cache — wired into `cve_lookup` for idempotent OSV lookups).

### Agents (8)
`recon` / `web-tester` / `auth-tester` / `cloud-iam` (finders) → **`verifier`** (refute-bias,
opus) → **`exploiter`** (chain-synthesis, opus, `mutation_testing`-gated) → **`reporter`** →
**`qa-auditor`** (opus). Mixed-model: mechanical stages on sonnet, judgment on opus.

### The chain-exploitation layer
The `exploiter` agent (post-verifier, pre-reporter) composes confirmed primitives into end-to-end
chains (JWT-forge→ATO, SSRF→metadata reach, gadget pingback, gated SQLi extraction, IDOR scale)
at their chain severity, with OOB confirmation (`oob.py`). Wired as `/pentest` Phase 3.5. When a
primitive/lead needs **bespoke exploit code no fixed probe covers** (custom signature gate,
app-specific logic flaw, odd serialization), the same agent opens the **exploit-dev lane** — a
one-off PoC under the gitignored `engagements/<name>/exploit-dev/` (copied from
`_template/exploit-dev/_poc_template.py`: a `control()`/`exploit()` delta that emits a `replay.py`
transcript and prints a LEAD). **Gated two ways** — `mutation-gate.py` hard-denies an
`exploit-dev/*.py` run unless `mutation_testing: approved` (the PoC path is on the command line;
its target/verbs are inside the .py, unseen by the host/verb scan), AND the scaffold's `_kit()`
self-checks fail-closed (approved + request host `in_scope`); same RoE (lifts nothing). A PoC
self-asserting success is a LEAD until the verifier reproduces the effect
by replay/re-derivation — never by re-running the script (`evidence-standard.md` → Bespoke-PoC
reproduction; `pitfalls.md` → "A PoC that prints SUCCESS"). Guarded by `doctrine_lint` C11 (no real
engagement data, incl. bespoke PoCs, may be git-tracked).

### Reporting + QA gate
Single-source `findings.json` → `report.md` + dark/light HTML + PDF (standalone: CSS + evidence
embedded inline; client logo). Per-finding OWASP/WSTG/ATT&CK + CVSS/CWE + coverage matrix +
limitations + compliance mapping. Export → SARIF/Jira/DefectDojo. The QA gate (mechanical
pre-flight → 5-lens panel → PASS/BLOCK) auto-runs at `/pentest` Phase 5.

### Built vs deferred
- **Client intake**: `/pentest-init` + `authorization.md` + `scope.yaml` per engagement.
- **Coverage**: full **web-application/site** surface (detector + breach-finder + chain-synthesis).
  Redan is **web only**. **Out of scope by choice**: network / host / Active Directory / mobile /
  white-box SAST.
- **Authenticated testing**: built + E2E-validated (canary IDOR oracle + json login + funclevel +
  massassign); needs provisioned TEST accounts for a real engagement.
- **Finding lifecycle / retest**: built — `finding_ledger` (stable `finding_uid` across engagements,
  fixed/still-open/new/regressed delta) + `/pentest-retest` + the report's Retest/Delta section.
  `/pentest-report` auto-records; the ledger lives at `engagements/_ledger.json` (gitignored).
- **Qualification** (human peer-review/sign-off): intentionally out of scope (the kit does tooling,
  not qualification).
- **Deferred** (need a prerequisite): `--remote`/scheduled intake; a multi-client portfolio
  dashboard over the ledger.
