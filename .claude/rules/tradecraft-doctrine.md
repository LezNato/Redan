# Tradecraft Doctrine

Meta-rules for HOW to test, distinct from the methodology pipeline
(`methodology.md`), the hard limits (`rules-of-engagement.md`), and the
finding bar (`evidence-standard.md`). These are discipline rules about the
*investigation process itself* — the things that keep an AI-driven assessment
from producing confident, plausible, false findings.

Load before chasing a lead, before calling a finding confirmed, before writing
the report.

## 1. Tag every claim: confirmed | refuted | lead

Never write "X is vulnerable" if X is a plausible story consistent with one
response but not directly proven. **confirmed** = you reproduced exploitation /
unauthorized access with your own evidence this engagement. **lead** = observed,
fits a vuln pattern, not yet proven. **refuted** = tested and ruled out. A
response that *looks* exploitable is not the same as a confirmed finding; saying
so makes a false positive a key part of the report.

**Failure mode:** a scanner flags "SQL injection possible" on a parameter and it
goes into the report. The param is reflected into a DB *type-cast* error that
never reaches a query — no injection. A scanner signal is a **lead**, not a
finding. (This is `evidence-standard.md`'s finding-vs-lead, stated as a tagging
discipline: tag before you write.)

**How to apply:** before writing any vuln statement, ask "what did I *observe*
that directly proves THIS, versus a story that would explain the response?" No
direct proof → tag `lead` and queue the confirming probe.

## 2. Test under every relevant state, not just the convenient one

A check that "passes" (or "fails clean") may only do so under one identity, one
auth state, one tenant, one browser, one region. The state you didn't test is
where the bug lives. Enumerate the states production exposes — anonymous / each
role / each tenant / pre- and post-auth / each region — and test the ones that
matter for the vuln class.

**Failure mode:** an endpoint returns another user's data when tested with the
*admin* session → "works as designed, admin can see everything." Re-tested with
a low-priv user (the state that matters for access control), it *still* returns
the data → that's the actual IDOR. The "clean" read came from testing under the
wrong identity. (Access control is meaningless tested as the privileged user.)

**How to apply:** for every access-control / authz check, name the identity the
result depends on and re-run under the least-privileged one. A negative result
under one state does not generalize to the others.

## 3. No scope-narrowing workarounds to dodge hard surface

When the real attack surface is hard to reach (request signing, anti-CSRF,
custom auth, a SPA that hides the API), fix the reach — don't quietly reframe the
test to the easy surface and call the engagement covered. Distinguish (a) it's
genuinely out of scope / infeasible → document and move on, vs (b) it's just
effort → do the effort.

**Failure mode:** the API needs an HMAC-signed request the tooling couldn't
reproduce, so testing was reframed to the public marketing pages. Reversing the
JS signer was ~20 minutes; skipping it left the *actual application* — the real
attack surface — untested while the report implied coverage. Silent coverage
gaps read as "tested and clean."

**How to apply:** if you bound coverage (couldn't auth, couldn't sign, skipped a
host), **say so in the report** — an untested area is not a clean area.

## 4. Don't infer / assume / guess — separate observation from explanation

State only what you observed. A version banner, a framework fingerprint, a
suggestive error are **observations**; "therefore vulnerable to CVE-X" is a
**candidate explanation**, not a fact, until you demonstrate it on *this* target.

**Failure mode:** a report drafts "CVE-2021-XXXX RCE confirmed" from an nginx
`Server:` banner. The banner was a static string behind Cloudflare; the origin
version was unknown and the CVE path wasn't reachable. A version match is a
**lead**.

**How to apply:** write "Observation: ⟨what the response showed⟩. Candidate:
⟨vuln⟩ (not yet confirmed)." Promote to a finding only after the confirming
exploit/repro runs and you read its result.

**Sub-rule — never write a specific value before you've observed it; a tool
finishing is not a verdict.** Do not write a CVE id, a CVSS score, "RCE
confirmed", an exfiltrated record, or "admin access achieved" into a report /
notes / message until the evidence is in front of you *this turn*. A scan/exploit
process exiting means "the command ran" — NOT "the thing I wanted happened."
Read the actual output and map it to the right command (concurrent scans make
"it finished" ambiguous).

**Sub-rule — the confirming READ and the recording WRITE go in separate turns.**
The dominant fabrication is composing the finding text in the *same* step as the
request you expect to confirm it: the write pattern-completes "this looks
exploitable" from the prior response and you record a finding the actual result
may contradict. In turn N, run the confirming request and report what it showed
in prose only; in turn N+1 (result actually in context) write it into the report.
Never batch `run exploit` + `write "confirmed"` in one motion.

## 5. Independent verification — don't confirm a finding with the tool that found it

A finding and the method that produced it can share the same false assumption
and "agree" — a self-consistent false positive. Confirmation must come from an
*independent* method, environment, or vantage.

**Failure mode:** an XSS "confirmed" by the same crafted URL that surfaced it —
but it only fired because the tester's own browser had an extension stripping
CSP. In a clean browser it never executed. The finder and the "confirmation"
shared the same broken environment.

**How to apply:** this is the `verifier` agent's whole job — reproduce from a
clean state, with a different tool/session/browser than the finder used. If the
only thing supporting a finding is the finder's own transcript, it is a lead.

## 6. The report is canonical; the evidence trail is the devlog

`report.md` carries CANONICAL state — confirmed findings, current and
core. Raw scan logs, every 404, refuted hypotheses, and chronological
reasoning live in `engagements/<name>/evidence/` and `leads.md`. Don't paste the
devlog into the deliverable.

**Failure mode:** raw Burp history, every probe, and three refuted hypotheses
get pasted into `report.md`. The client can't find the two real findings. The
report is the signal; the history is the appendix/evidence.

**How to apply:** before adding to `report.md`, ask "is this a confirmed finding
the owner must act on, or the history of how I got there?" History goes to
`evidence/`.

## 7. Audit what you already captured before re-scanning

Before re-running a scan or proposing a new tool, search the evidence you already
have — the answer is often already in a captured response. Re-hammering the
target also burns the rate-limit / RoE budget for nothing. **Absence in your
grep ≠ absence in the response** (a pattern that only matched anchored lines
misses an indented one; a header you "didn't see" may be on GET but not HEAD).

**Failure mode:** about to launch a full directory brute-force for an admin
path — but it was already listed in the `sitemap.xml` captured during recon.
The brute-force adds noise, load, and RoE risk to rediscover known data.

**How to apply:** `grep` the `evidence/` capture with loose patterns first; re-
request the target only when the data genuinely isn't already in hand. Re-scans
are a last resort, not a first reflex (also honors the no-DoS / rate-limit RoE).

## 8. One observation is noise — reproduce through WAF/cache/LB intermittency

A single anomalous response can be infrastructure noise, not a vuln: a cached
response, a WAF that intermittently blocks, a load balancer hitting one flaky
backend, a rate-limiter kicking in. Reproduce before you claim.

**Failure mode:** a single `500` read as "I crashed the app / DoS." Re-run 5×:
it was an LB occasionally hitting one bad backend — intermittent, not attacker-
controlled. Conversely a payload that "worked once" may have hit an uncached
path; a WAF blocks it on retry.

**How to apply:** confirm a finding across multiple attempts, and where relevant
across sessions / accounts / source IPs / cache-busting params, before it's a
finding. Structural conclusions can hold even when a specific timing/value
fluctuates — but the *existence* of the effect must reproduce.

## 9. Notes/report hygiene — a downgrade REPLACES the finding, never sits beside it

`report.md`, `leads.md`, and memory are re-read by future sessions (and by the
client). When a finding is downgraded or refuted, **move it** — do not leave the
original "High" inline with a "retracted" note beside it. A reader (or the
recalled summary / exec-summary count) will carry the wrong version.

**Failure mode:** a finding cut from High to false-positive is left in the
Findings section with a "NOTE: retracted" line; the exec summary still counts it
as a High. The client sees a High that doesn't exist.

**How to apply:** on any downgrade/retraction — fix the exec-summary counts
first (that's the recalled summary), move the item to `leads.md` (or delete with
the lesson preserved), and grep `report.md` to confirm the old claim survives
nowhere as a live statement. (Memory-side mirror of §6: §6 says *where* content
belongs; §9 says *delete the stale layer* so it stops being re-injected.)

## 10. Corroborate external claims — an uncorroborated CVE is a lead, not a fact

A CVE id emitted by a research/scanner tool is a **claim**, not a verified fact. AI research
workflows hallucinate CVE ids; OSV returns a silent `{vulns:[]}` (a coverage gap) for whole
ecosystems (e.g. WordPress plugins) that *reads* as "clean" but isn't. State a CVE as fact
**only after corroborating it against ≥2 authoritative sources** (NVD / GitHub Advisory GHSA
/ WPScan / Patchstack / Wordfence / the vendor). An uncorroborated CVE goes in as a **lead**
with the corroboration gap flagged — never as a confirmed finding, and never dismissed as
"hallucinated" on the strength of a single refusal-flavored search snippet either.
**Corroborate BEFORE you assert OR dismiss** — the dominant failure is over-trusting one
source in either direction. (Real failure mode: a research workflow emitted a real CVE; an
over-trusted search snippet then called it "hallucinated"; only GHSA/NVD/WPScan corroboration
resolved it.) The `plugin_cve_research` workflow enforces this with a ≥2-source
corroboration gate; the QA gate's cve-corrob lens double-checks it.

## When to load this file
- Before chasing a lead toward a finding (pairs with `engagement-loop.md`).
- Before tagging any finding `confirmed`.
- Before writing or regenerating `report.md`.
- During any post-run review where the operator pushed back on a finding —
  record the failure mode under the relevant rule above.

## Cross-references
- `engagement-loop.md` — the loop each rule plugs into (steps cite §1/§4/§5/§7/§8/§9).
- `evidence-standard.md` — the finding-vs-lead bar §1 enforces.
- `rules-of-engagement.md` — §3/§7 honor the scope + rate-limit limits.
- `methodology.md` — the macro pipeline this doctrine disciplines.
