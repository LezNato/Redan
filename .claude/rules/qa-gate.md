# QA Gate — a report is not deliverable until it passes

The pre-delivery quality gate. A report that has not passed this gate is a draft,
not a deliverable — never hand one to a client (or treat it as final) until the
`qa-auditor` has run it and returned PASS. Independent and SEPARATE from the
`reporter` (the author does not grade their own work).

This exists because real failures happened on live runs (see CLAUDE.md status):
a report that was "ready" but never written to disk; CVE IDs asserted past the
tester's knowledge cutoff; a verify pass that refuted 0 of 18 candidates. The
gate is the backstop for exactly those.

## The gate (every item must pass)

**1. Deliverable integrity** — **[MECHANICAL]** (`ls` + `finding_schema.py`)
- `engagements/<name>/report.md` EXISTS on disk (not "ready to write" — `ls`/Read it).
- Every evidence artifact referenced in the report exists under `evidence/`.
- The appendix evidence index matches the actual files present.

> **Decision authority per item**:
> **[MECHANICAL]** = a deterministic tool auto-fails it (no judgment).
> **[DIRECTIONAL]** = agent judgment, but must log a one-line reason.
> **[RESERVED]** = operator-only — the agent SURFACES it and never decides.
> Run the two mechanical validators first; they cover items 1 (index/reference
> integrity), 2, 3, 5 (count-drift), 6: `python tools/checks/finding_schema.py
> engagements/<name>/findings.json` and `python tools/checks/redact.py scan
> engagements/<name>`. `finding_schema` now also catches **dangling finding-id
> references** (a `ref` left behind after a move/downgrade, §9) and **summary-count
> drift** (the prose says "3 leads" but the array has 5) — classes the LLM gate used
> to catch, now deterministic. The `qa-gate` workflow runs this pre-flight FIRST and
> short-circuits to BLOCK if it fails, so the Opus panel is spent only on the
> judgment-heavy semantic checks.

**2. Finding integrity** (per confirmed finding) — **[MECHANICAL]** (`finding_schema.py`)
- Has ALL of: location, reproduction steps, an evidence artifact, CVSS 3.1
  vector + score, CWE, concrete impact, remediation, verification note.
- No finding lacks a reproduction (if it does → it belongs in Leads, not Findings).

**3. Severity discipline** — **[MECHANICAL]** (`finding_schema.py`) + **[DIRECTIONAL]** (scope-appropriateness)
- Severity not inflated ABOVE its CVSS band (down-rating is allowed/encouraged).
- No `informational` item is rated as a finding severity.
- Exec-summary severity counts EQUAL the actual findings by severity.
- A finding scored as a chain has the end-to-end chain demonstrated.
- Each finding carries a `validation_status` (verified/available/unconfirmed); a
  non-`verified` High is downgraded absent strong cause.
- *Directional:* is the severity appropriate for THIS scope/business context?

**4. External-claim corroboration** (the CVE-cutoff backstop) — **[DIRECTIONAL]**
- Every CVE id / external advisory is corroborated by ≥2 authoritative sources.
- Any CVE that postdates the tester's knowledge cutoff is FLAGGED in the report
  for vendor/WPScan/NVD confirmation before third-party delivery.
- A component finding where exploitation was NOT performed says so explicitly —
  "vulnerable version present; exploitation not demonstrated", never implies a
  live exploit it didn't run. (Pairs with `pitfalls.md` "version banner ≠ vuln".)

**4b. Number integrity** — **[DIRECTIONAL]**
- Each CVSS/CWE/count in `findings.json` traces to an `evidence/` source (it was
  read, not guessed; recorded in a separate step from the probe that produced it).
  See `evidence-standard.md` → Number integrity.

**5. Disposition hygiene** (`evidence-standard.md` vocabulary) — **[DIRECTIONAL]** (count-drift via `finding_schema.py`; disposition placement/exclusion is agent-judged)
- Canonical dispositions used; `refuted`/`duplicate`/`out-of-scope` items are NOT
  sitting in the Findings section.
- Any downgrade REPLACED the prior claim (and the exec-summary count) — not left
  inline beside a "retracted" note (`tradecraft-doctrine.md` §9).

**6. Redaction — [MECHANICAL]** (deterministic, BLOCKING — do not eyeball) — run
`python tools/checks/redact.py scan engagements/<name>`. A nonzero exit means
unredacted credential material (Authorization / Cookie / Set-Cookie / JWT /
api_key / password) somewhere in the engagement tree — evidence referenced or
not, `leads.md`, `findings.json`, `report.*` — which is a **BLOCK**. Fix with
`python tools/checks/redact.py file <path>` (redacts values, preserves Set-Cookie
attributes), then re-scan until clean. Authenticated engagements MUST pass this.

**7. Coverage honesty** — **[RESERVED]** (operator sign-off) — a coverage/standards
statement is present; any surface that was not tested (couldn't auth, skipped
host, out-of-time) is STATED, not silently omitted (`tradecraft-doctrine.md` §3).
*Whether coverage is sufficient to sign off is the operator's call, not the agent's.*

**8. RoE compliance** — **[DIRECTIONAL]** — the report's own RoE section is truthful:
non-destructive confirmed, any active exploitation was authorized, stop-on-real-data
honored.

## Verdict
`PASS` (deliverable) or `BLOCK` (not deliverable) + a list of blocking issues,
each tied to the gate item it failed. A single BLOCK item means the report is not
client-ready. Fix and re-run the gate.

## Cross-references
- `qa-auditor` agent runs this gate; `/pentest-qa` skill orchestrates it.
- `evidence-standard.md` (the finding bar + dispositions), `tradecraft-doctrine.md`
  (§3 coverage, §9 hygiene), `pitfalls.md` (false-positive catalog),
  `methodology.md` (the gate runs as the phase between reporting and delivery).
