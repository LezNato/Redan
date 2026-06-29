# The Engagement Loop — chasing one lead to an honest conclusion

The **orchestration layer** above the other rule files. Where
`tradecraft-doctrine.md` gives the *discipline rules* (tag claims, don't guess,
verify independently), `evidence-standard.md` gives the *bar* (finding vs lead),
and `methodology.md` gives the *macro pipeline* (recon → test → verify → report),
**this file gives the LOOP** — the repeatable sequence that turns a single lead
("endpoint returns 200 for another user's id") into either a **confirmed
finding** or an **honest closure** (refuted / informational / out-of-scope).

It runs *inside*
methodology phases 3–4: recon surfaces leads; for **each** lead you run this loop.
It is designed to be **automatable** by the agent ensemble — each step names its
doctrine rule, its concrete probe, and the agent/Workflow shape that runs it.
**Step 4 (which exploit angle) and step 8 (disposition + the stop-on-real-data
call) are judgment-heavy** — keep a human or a deliberately-gated agent on those.

## When to run this loop
- Recon / a scanner / a finder agent surfaced a lead.
- A response surprised you and you don't yet have a proven vuln.
- You're tempted to write "confirmed" — STOP and run step 5 first.

## The loop
Run top to bottom. Most steps can **redirect** back to step 3 (a probe sharpens
what the vuln actually is and changes the next probe). The loop ends at
**confirmed** (capture evidence → verify → report) or **honest closure**
(refuted / informational / out-of-scope, recorded in `leads.md`).

### 1. Pick the lead — characterize the observation, not the fix
State the lead as an *observation*, not a verdict: which endpoint/param/resource,
what the response showed, under which identity. Resist naming the vuln yet.
- **Doctrine:** §1 (tag as `lead`), §4 (observation, not explanation).
- **RoE:** confirm it's `in_scope` before you touch it.
- **Automatable:** a finder agent emits `{location, observed_response, identity,
  candidate_class}` — already the shape `web-tester`/`cloud-iam` return.

### 2. Audit prior art FIRST — before exploiting or proposing
Search what you already have and what's already known: the recon evidence, the
target's own docs/changelog, public disclosures / CVEs / the bug-bounty program's
known-issues and duplicates. **A lead that "feels new" is often already in your
capture or already disclosed.**
- **Doctrine:** §7 (audit captured evidence before re-scanning).
- **Tools:** `grep` over `engagements/<name>/evidence/`; `WebSearch` for the
  CVE / disclosed report; check the program's out-of-scope & known-issues list.
- **Automatable:** an `Explore` / `recon`-agent fan-out over `evidence/**` +
  web, returning `known-dup | known-cve | novel` with the citing source.

### 3. Cheap-probe-first — the cheapest request that splits two hypotheses
Before any exploit chain, write **two named hypotheses** (real vuln vs benign
explanation / false positive) and run the cheapest test whose result differs
between them. Order: re-read the captured response (free) → one crafted request →
full chain (last).
- **Doctrine:** §1, §4. **Bar:** `evidence-standard.md`.
- **Automatable:** a `parallel()` of probe-agents, one per hypothesis-splitter.
- **Anchor (a real engagement):** a reflected-parameter DOM-XSS lead was
  split by a **free static read** of the param's handler script — the value is
  allowlisted to a fixed set before any sink. One read refuted it; no payload, no
  browser, no noise.

### 4. Sharpen iteratively — let each probe redirect the next
The judgment-heavy core. Each probe *re-localizes* the vuln; follow the redirect
instead of forcing the first framing. Is it IDOR or a deliberately-public
endpoint? Stored or reflected? Auth bypass or just a verbose error? Build the
next probe for the *new* localization.
- **Doctrine:** §4 (separate observation from explanation each hop).
- **Automatable (partial):** re-run step 3 with the updated hypothesis pair; the
  *choice* of next splitter is the creative/human part, the "name two
  hypotheses, find the divergent request" is the guardrail.

### 5. Lock predictions, build the falsification IN
Before running the confirming exploit, write what you expect **if real** vs **if
false-positive**, and include a **control** — a request that *should* be denied/
safe — so the result is decisive either way. A finding proven only by the
positive case, with no control, is weak.
- **Doctrine:** §1 (tag), §4 (read result before recording).
- **Tool:** a paired test — `{the exploit request, a control that should fail}` —
  from the same session/state.
- **Anchor:** for an IDOR, the control is "the same request for an object you DO
  own succeeds; for one you don't, it should 403 — if it 200s, that's the bug."
  The deny-case IS the falsification control.

### 6. Reproduce — clear infrastructure noise before claiming
One success can be a fluke (uncached path, WAF gap); one failure can be noise (LB,
rate-limit). Reproduce the effect across multiple attempts — and where it matters
across **accounts / sessions / source IPs / cache-busting** — before it's a
finding.
- **Doctrine:** §8 (one observation is noise).
- **RoE:** rate-limit the repeats; reproduce ≠ hammer. One clean PoC pair is
  enough — don't enumerate (`rules-of-engagement.md`).

### 7. Verify independently — skeptic + RoE/quality auditor
Hand the candidate to a verifier that tries HARD to **refute** it (find any way
it's a false positive / already known / not actually exploitable) and an auditor
that checks discipline (is "confirmed" earned? independent repro per §5? severity
honest? in-scope and non-destructive?).
- **Doctrine:** §5 (independent verification), §1 (tag).
- **Tool:** the `verifier` agent — or an example skeptic/auditor lens pair
  (skeptic: `{verdict, strongest_refutation, reproduced}`; auditor:
  `{confirmed_earned, severity_honest, roe_clean, independent_repro}`).
- **Automatable:** the committed implementations are the single-opus-verifier
  verify stage in `pentest-assess.js` and the 5-lens `qa-gate.js` panel.
  Only findings that survive proceed to the report.

### 8. Honest bookkeeping — capture, tag, close
- **Tag** the outcome using the canonical dispositions (`evidence-standard.md`):
  `confirmed` / `informational` (→ report) · `lead` / `refuted` / `duplicate` /
  `out-of-scope` (→ `leads.md`).
- **Never** write a value you haven't read this turn; **never** batch the
  confirming read with the recording write (doctrine §4 sub-rules). On an
  autonomous/loop turn, "still verifying — nothing confirmed yet" is a valid
  output; don't let the cadence manufacture a finding.
- **Capture evidence** (request/response, screenshot, transcript) to
  `engagements/<name>/evidence/`, secrets/PII redacted, **before** moving on —
  a promising lead you didn't capture is unreconstructable once the session/token
  rotates.
- **Disposition (RoE):** non-destructive PoC only; on real user data, one
  redacted proof then **STOP** — do not enumerate. This is the judgment call to
  keep a human on.
- **Hygiene** (doctrine §9): a downgrade REPLACES the finding (and the exec-
  summary count), it doesn't sit beside it.

## Automatable vs judgment
| Step | Automatable? | Shape |
|---|---|---|
| 1 pick/characterize | yes | finder agent → `{location, observed, identity, class}` |
| 2 prior-art audit | yes | `Explore` fan-out over `evidence/**` + WebSearch (known-dup/cve/novel) |
| 3 cheap-probe | yes | `parallel()` of probe-agents, one per hypothesis-splitter |
| 4 sharpen/redirect | **partial — the core judgment** | doctrine as guardrail; the splitter *choice* is creative |
| 5 lock + control | yes | paired `{exploit, control-that-should-fail}` from one state |
| 6 reproduce | yes | re-run N× (+ multi-account/IP) under a rate cap |
| 7 independent verify | yes | the `verifier` agent / skeptic+auditor `Workflow` |
| 8 bookkeeping | partial | tagging + evidence capture are mechanical; the read-before-write *separation* and the stop-on-real-data call must stay gated |

The honest automation boundary: an autonomous loop can run 1–3, 5–7 mechanically
and propose step-4 redirects, but a human (or a gated agent) should approve the
**step-4 exploit angle** and the **step-8 disposition** — the two places where
over-confidence fabricates a finding or crosses an RoE line.

## The shape of a good worked example
A clean lead reads as: **observation → prior-art audit → cheap probe → redirect →
cheap probe → … → a single proven cause → control + reproduce → independent
verify → confirmed finding** — or honest closure. The number of redirects is the
signal the loop was driven by probes, not guesses. A refutation *inside* the loop
(the lead was a false positive) is not a failure — it's the discipline catching
over-reach before it reached the report. That reflected-param lead is the
minimal worked example: one cheap static read closed it honestly as refuted.

## Cross-references
- `tradecraft-doctrine.md` — the discipline rules each step cites (§1/§4/§5/§7/§8/§9).
- `evidence-standard.md` — the confirmed-finding bar steps 5–8 enforce.
- `rules-of-engagement.md` — the rate-limit / non-destructive / stop-on-data limits.
- `methodology.md` — the macro pipeline this loop runs inside.
- The `Workflow` tool — the automatable substrate for steps 2, 3, 7.
