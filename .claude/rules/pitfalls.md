# Pitfalls — the false-positive catalog

Concrete, recurring traps where something *looks* like a finding but usually
isn't. This is the `verifier`'s reference and the `web-tester`/`cloud-iam`
self-check: before tagging anything `confirmed`, find it here and run the
"confirm or kill" probe. Each entry follows the format
(Symptom → why it fools you → the decisive test).

A false positive in a client report costs more than a missed lead — it burns
credibility and the client's remediation budget. Killing these is the single
highest-value thing the toolkit does.

> Tagging vocabulary is defined once in `evidence-standard.md` (confirmed / lead
> / refuted / duplicate / informational / out-of-scope). Everything below ends
> in one of those.

## Injection / XSS

**Reflected input ≠ XSS.** Your payload appears in the response → looks like XSS.
Reflection is necessary, not sufficient: it must land in an executable context
*and* execute. **Confirm or kill:** prove script execution (a real `alert`/DOM
change/exfil callback) in the rendered page, in a clean browser; identify the
exact sink and that output encoding doesn't neutralize it. Reflected-but-encoded
→ `refuted`.

**Self-XSS isn't a finding.** A payload you type into your own field that
executes in your own browser has no attacker delivery path. **Confirm or kill:**
is the input deliverable by an attacker (URL param, stored value another user
renders, request another user's browser makes)? No delivery vector → `refuted`
or at most `informational`. (This is a common SPA / demo-site case.)

**"SQL error" ≠ SQL injection.** A 500 or a database error string can come from a
type cast, a malformed input the app rejects, or an ORM guard. **Confirm or
kill:** demonstrate *query control* — boolean-based (true/false pages differ),
time-based (controlled delay), or UNION/extracted data. A stack trace alone is
`informational` (verbose errors), not SQLi.

**Stored "XSS" that only you see.** Payload stored and rendered back, but only in
a view scoped to your own session/account. **Confirm or kill:** prove it renders
in a *different* user's (or admin's) context. Self-stored → `refuted`.

## Access control / auth

**A 200 isn't unauthorized access — check the identity.** An endpoint returning
data "for another user's id" while you're testing as admin/owner proves nothing.
**Confirm or kill:** re-run as the *least-privileged* identity that should NOT
have access; the bug is a 200 where a 403 belongs (doctrine §2). Tested-as-
privileged → not yet a finding.

**Username enumeration is usually Low.** Different error/timing for valid vs
invalid users. **Confirm or kill:** confirm the signal is reliable (not noise,
doctrine §8) AND that it has impact (no other control depends on secrecy of
usernames). Often `informational`.

**Login/logout CSRF is usually Low/none.** CSRF on authentication endpoints
rarely has real impact, and many "CSRF" hits are protected by SameSite cookies or
a token you missed. **Confirm or kill:** identify a *state-changing,
security-relevant* action with no anti-CSRF (token/SameSite/origin check), and
forge it cross-site end-to-end.

## Network / SSRF / config

**CORS `Allow-Origin: *` is usually safe.** A wildcard ACAO without
`Allow-Credentials: true` exposes only data any anonymous client could already
fetch. **Confirm or kill:** the real bug is a *reflected arbitrary origin* WITH
`Allow-Credentials: true` on an authenticated, sensitive endpoint. Wildcard on
public data → `informational` at most.

**SSRF callback ≠ exploitable SSRF.** A DNS lookup or HTTP hit to your collaborator
proves the server makes a request; it doesn't prove reach to anything sensitive.
**Confirm or kill:** demonstrate reach to an internal resource, cloud metadata
(169.254.169.254 / metadata.google.internal), or a port/service the attacker
shouldn't touch. Blind-DNS-only with no internal reach → `lead`, not `confirmed`.

**Open redirect needs cross-origin + impact.** Many "redirects" stay same-origin,
require already-trusted input, or are intended (post-login `returnUrl`). **Confirm
or kill:** force a redirect to an *attacker-controlled external* origin, and name
the impact (phishing, OAuth token theft via redirect_uri). Otherwise `informational`.

**Missing security header ≠ High.** Absent CSP / HSTS / X-Frame-Options /
Permissions-Policy is hardening, not an exploit. **Confirm or kill:** rate as
`informational`/Low unless you can *chain* it into a demonstrated exploit (e.g.,
no X-Frame-Options + a sensitive one-click action = a real clickjacking PoC).
"Missing CSP = High XSS" with no XSS is the classic inflated finding.

**Subdomain-takeover "candidate" must be claimable.** A dangling CNAME to a
deprovisioned service looks takeoverable. **Confirm or kill:** verify you can
actually register/claim the target resource (within RoE — claim only if
authorized and non-disruptive). Unclaimable / already-owned → `refuted`.

## Recon / disclosure

**Not every exposed file is sensitive.** A reachable `/commit.json`, `/.well-known`,
public `sitemap.xml`, or a build manifest may be intentional. **Confirm or kill:**
read it — does it expose secrets, internal paths, or PII? Benign public metadata
→ `informational` or non-issue (a public `/commit.json` build manifest is the classic example).

**Every path "reachable" → it's a WAF/challenge shell, not exposed files.** An edge
JS proof-of-work challenge (Imunify360 "One moment, please...", Cloudflare "Checking
your browser") or a soft-404/SPA catch-all returns a *uniform* `200` (or `415`/`403`)
page to non-JS clients for ANY path — so a path-prober / `curl` reports `.git/config`,
`.env`, `id_rsa`, `.aws/credentials`, `Dockerfile` all "reachable." These are the
**single most dangerous false positive** (fabricated criticals). **Confirm or kill:**
read the BODY and compare to a known-nonexistent random path — same page/length ⇒
it's the shell, `refuted`. Run `tools/checks/waf_detect.py` FIRST; on a `js-challenge`,
urllib/curl tools are blind (they cannot solve the JS PoW — neither can a basic
attacker scanner) — re-test the path through the **browser channel** (a real
top-level navigation passes the challenge) before believing ANY "exposure."
`path_probe.py` auto-detects this (multi-baseline calibration + 200-cluster
detection), but a hand-rolled `curl` or a brand-new tool WILL be fooled. (On one
WAF'd site a path-prober produced ~15 of these ghosts; every one was killed by reading the body.)

**Not every key is a secret.** Client-side "API keys" are often *meant* to be
public — Stripe **publishable** keys, Firebase web API keys, Google Maps browser
keys, Sentry public DSNs. **Confirm or kill:** identify the key type; test whether
it grants privileged access. A publishable/restricted key → `informational` or
non-issue. A leaked *secret* key (server-side, write-capable) → real, high.

**Version banner ≠ vulnerability.** A `Server:`/framework version mapped to a CVE
is a `lead` (doctrine §4). **Confirm or kill:** banners are frequently static,
spoofed, behind a CDN, or back-port-patched. Demonstrate the CVE's behavior on
*this* target, or downgrade to `lead`/`informational`.

## Infrastructure-noise traps (see doctrine §8)

**One 500 ≠ DoS.** A single error can be an LB hitting a flaky backend or a
rate-limiter. Reproduce 5×+; intermittent infra noise → not a finding. And note
RoE forbids DoS/stress testing regardless.

**"It worked once."** A payload succeeding once may have hit an uncached node or a
WAF gap; retried, it's blocked. A finding must reproduce (doctrine §8) and the
PoC must be reliable enough to hand a client.

**OSV misses WordPress plugins.** `cve_lookup.py` (OSV.dev) returns 0 vulns for ALL WP plugins
(it is a coverage_gap, NOT 'no CVEs'). **Use the `plugin_cve_research` workflow** — it
web-researches each plugin+version across NVD/Wordfence/Patchstack/WPScan. On a real WordPress
engagement this surfaced a handful of overlooked version-match CVEs that OSV completely missed. **Confirm or kill:** a version match is a lead; demonstrate the CVE on-target
(or note the defense layer — WAF/HMAC/config — that blocks it).

## Attacker-effectiveness false positives

**Race: concurrent ≠ serial is not always a race.** A one-shot action consumed by the serial phase
gives concurrent=0 (correct behavior, not a race). Use concurrent-FIRST + `--max-expected` (default
1 for one-shot; K for continuous). A healthy locked endpoint gives concurrent=1; concurrent>1 = race.
**Confirm or kill:** is the concurrent effect count > what a healthy endpoint should produce?

**SSPP: pollution that surfaces only on a LATER request.** A single-request test misses it. Send the
pollutant, then RE-READ a decision endpoint that reads the polluted key as a fallback. Accepted-but-
no-flip = a merge-sink LEAD, not a finding. **Confirm or kill:** does a privileged decision flip?

**Cache deception needs an AUTHED victim.** The path-confusion request alone is a LEAD. The proof:
an authed session populates the cache (fetches `/account;.css`), then an anon fetches the cached
copy and sees private data. Without the authed-populate step, it's unconfirmed.

**H2 smuggling: timing differential ≠ smuggling.** A timeout or status differential is a LEAD. Confirm
with a real smuggled request that poisons another user's response (operator-gated). Full H2.CL/H2.TE
needs the `h2` library (frame-level crafting).

**Business-logic: accepted-value ≠ bug.** A coupon/price/quantity the server accepts is NOT a finding
unless it violates the DOCUMENTED intent. `flow_probe` flags diffs; the agent must interpret whether
the diff is a real business-rule violation. "Server accepted quantity=-1" is a lead until you confirm
-1 is not a valid intended value.

**WAF bypass: reaching the origin ≠ exploitation.** A variant that passes the WAF is a LEAD. Chain the
REAL payload via the working variant to demonstrate impact. A bypass that delivers nothing is info.

**Clickjacking: frameable ≠ exploitable.** Frameable + a sensitive one-click state-changing action =
the finding. Frameable + no sensitive action = informational (hardening, like F-07's missing XFO).

**OOB callback ≠ the bug.** A callback proves the server made a request (SSRF/XXE reach); it does NOT
prove reach to anything sensitive. Internal-reach to metadata/127.0.0.1 = the finding; a callback to
an external host with no internal reach = a lead.

## WAF SQL-signature bypass (keyword rules + inline-comment / error-based evasion)

**Imunify360-class WAFs match dangerous FUNCTION names, not operators.** A payload using
`SLEEP()` / `BENCHMARK()` / `UNION SELECT` is 403'd at the edge; but **inline-comment
fragmentation** (`SLEEP/**/(5)`, `UNION/**/SELECT`) splits the keyword and **bypasses the
signature** (observed: bare `SLEEP(5)` → 403; `SLEEP/**/(5)` → 200 past the WAF). **Confirm
or kill:** when a SQL payload is WAF-403'd, try the inline-comment variant before concluding
the sink is unreachable — a WAF block ≠ the app rejecting the payload. (The bypass only
defeats the edge signature; reaching the sink still needs the right param/context.) Also:
**error-based SQLi** (`extractvalue`/`updatexml`) is typically **WAF-clean** (not in the
keyword ruleset) — use it as the time-based alternative when `SLEEP` is keyword-blocked.
Deliver payloads through the browser channel (`methodology.md` → Edge-WAF channel routing)
so they actually reach the handler.

## Cross-references
- `evidence-standard.md` — the disposition vocabulary and the confirmed bar.
- `tradecraft-doctrine.md` — §1 (tag), §2 (test the right identity), §4 (banner ≠
  vuln), §5 (independent verify), §8 (noise).
- `engagement-loop.md` — step 7 (independent verify) consults this catalog.
