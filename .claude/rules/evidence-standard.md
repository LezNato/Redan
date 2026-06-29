# Evidence standard — what counts as a finding

> **Every FINDING traces to a reproduction. No reproduction → it is a LEAD, not
> a finding, and it does not go in the report.**

This is the single discipline that makes an AI-driven pentest trustworthy. The
common failure mode is confident, plausible, *false* findings. We kill that
class by requiring reproducible evidence and independent verification.

## Disposition vocabulary (canonical — used everywhere)

Every observation ends in exactly one disposition. This table is the single
source of truth; `tradecraft-doctrine.md` §1, `engagement-loop.md` step 8, the
`verifier` agent, and `pitfalls.md` all use these terms.

| Disposition | Meaning | Where it goes |
|---|---|---|
| `confirmed` | Reproduced + independently verified exploit/impact | `report.md` → Findings (severity-rated) |
| `informational` | Real but not directly exploitable; low / accepted risk (hardening, disclosure, weak config) | `report.md` → Informational/Hardening |
| `lead` | Observed, fits a pattern, not yet proven | `leads.md` (follow-up) |
| `refuted` | Tested and ruled out — a false positive | `leads.md` (with the killing reason) |
| `duplicate` | Same root cause as another finding, or already-known/disclosed | noted once, not re-reported |
| `out-of-scope` | Belongs to excluded surface | dropped (record why) |

Only `confirmed` and `informational` reach the client report. `confirmed`
carries a severity; `informational` never inflates into one.

### Confidence basis — `validation_status` (per finding)

Disposition says *what bucket*; `validation_status` says *how sure*, machine-checkably:

| `validation_status` | Meaning |
|---|---|
| `verified` | independently reproduced (a PoC re-run from a clean session by the verifier) |
| `available` | payload crafted / path plausible, but NOT executed against the target |
| `unconfirmed` | a single signal, not reproduced |

A confirmed finding should be `verified`. An `unconfirmed` item must carry a
recommended follow-up test, and the `verifier` downgrades a non-`verified` High→
Medium absent strong cause. The `validation_status` enum and severity-vs-CVSS-band are
validated by `finding_schema.py`; the High→Medium downgrade itself is a verifier judgment
(qa-gate item 3).

## A finding MUST have
1. **Title + class** — what it is (e.g. "IDOR on /api/orders/{id}", CWE-639).
2. **Location** — exact URL/endpoint/parameter/resource.
3. **Reproduction** — the literal steps: request(s) + response(s), command +
   output, or a click-path. Enough that someone else reproduces it cold.
4. **Evidence artifact** — saved under `engagements/<name>/evidence/`:
   request/response capture, screenshot, or command transcript. Secrets/PII
   redacted.
5. **Impact** — what an attacker gains, concretely. Not "could be serious."
6. **Severity** — CVSS 3.1 vector + score, plus a one-line justification.
7. **Verifier verdict** — confirmed-reproduced by the `verifier` agent, with
   how it was independently checked.
8. **Remediation** — the specific fix.

## Leads (kept separate, never reported as findings)
Anything observed but not yet reproduced/exploited: an interesting parameter, a
verbose error, a tech version with known CVEs not yet confirmed exploitable.
Leads live in `engagements/<name>/leads.md` for follow-up.

## Severity-scoring discipline

Severity errs toward optimism — the instinct inflates. Correct downward and make
every CVSS metric earn its value from *demonstrated* impact on THIS target.

1. **Decompose before you score.** From the evidence, name each axis explicitly:
   attack vector (N/A/L/P), privileges required (PR — did you need an account?
   which role?), user interaction (UI), scope change (S — did you cross a trust
   boundary?), and the C/I/A you actually *demonstrated* — not the worst case the
   vuln class can theoretically reach. A finding without this decomposition is
   not ready to score.
2. **Score the demonstration, not the class.** "IDOR" is not automatically High.
   An IDOR leaking another tenant's PII at PR:L is; one exposing a non-sensitive
   setting is Low. CVSS comes from what you reproduced.
3. **No informational inflates to a High.** Missing headers, verbose errors,
   version banners → Low/Info unless chained into a demonstrated exploit.
4. **Score a chain AS the chain — and demonstrate it.** Low + Low → High only
   when you show the end-to-end chain. Otherwise report the parts at their own
   severity and note the theoretical chain as a `lead`.
5. **Record the CVSS 3.1 vector string + a one-line justification** tying each
   non-trivial metric to evidence. The client's remediation priority and the
   retest both depend on it.
6. **One scale across the engagement** — map CVSS band → client severity
   consistently (Critical 9.0–10 / High 7.0–8.9 / Medium 4.0–6.9 / Low 0.1–3.9 /
   Info 0.0).

A version-number match is a `lead` until exploitability is shown on this target;
a known/previously-reported issue is a `duplicate`, not a re-report (see the
disposition table).

## Number integrity (no fabricated scores)

A CVSS score, CWE, or count is a *measurement*, not a guess — and the dominant
failure is writing the number in the same motion as the scan you *expect* to
produce it (you pattern-complete the prediction). So:

1. **Write the number in a separate step, AFTER you've read its source.** Read
   the scan/probe output in prose first; persist the CVSS/CWE/count into
   `findings.json` only once the value is actually in front of you. Never batch
   "run the check" with "record the score."
2. **Name what the number literally measures** before recording it: a PoC-only
   lower bound, an assumes-perfect-exploit upper bound, or a measured/reproduced
   point — and that it's the decision quantity (don't record tool-certainty as
   exploitation-probability).
3. Every number in `findings.json` must trace to an `evidence/` source. The
   `finding_schema.py` validator enforces structure (band, counts); the QA gate's
   number-trace check (directional) confirms each score traces to evidence.
