# Methodology — the ensemble playbook

The toolkit runs a target through phases. Each phase is one or more **specialty
agents** (`.claude/agents/`). The orchestrator (you, or the `/pentest` skill)
reads `scope.yaml`, fans agents out, and synthesizes. Findings are not trusted
until the **verifier** has tried to refute them.

```
            scope.yaml  (the gate — read FIRST, every phase)
                 │
   ┌─────────────┼──────────────────────────────┐
   ▼             ▼                                ▼
[recon]    [web-tester]   [cloud-iam]      (parallel finders)
   │             │              │
   └──────┬──────┴──────────────┘
          ▼
     candidate findings  ──►  [verifier]  ──►  survivors only
                                                   │
                                                   ▼
                                              [reporter]  ──►  report.md  ──►  [qa-auditor] (PASS/BLOCK)  ──►  deliverable
```

## Phases

1. **Scope load.** Read `scope.yaml`. Confirm the target is `in_scope` and you
   are authorized. If scope is empty/placeholder, STOP and ask the operator.
2. **Recon (passive surface).** `recon` agent: subdomains, DNS, tech
   fingerprint, exposed surface, public artifacts. No active exploitation.
3. **Enumeration + testing (active, in parallel by domain):**
   - `web-tester`: auth/session, access control (IDOR/BOLA), injection, SSRF,
     misconfig, secrets in responses. Uses the browser + Playwright tools.
   - `cloud-iam`: public cloud posture — exposed buckets/endpoints, IAM
     over-permissioning *observable from outside*, leaked keys, metadata SSRF.
   - `auth-tester` (only when the engagement provisions TEST accounts in
     `roles.json`, out of tree): the post-login surface — IDOR/BOLA, privilege
     escalation, multi-tenant isolation, function-level access control.
     READ-ONLY by default (mutation-gate hook); proves IDOR via the canary/4-cell
     oracle (`auth_request.py --idor`), never by enumerating real users' data.
4. **Verification (independent).** Every candidate finding goes to `verifier`,
   which tries to **disprove** it and to reproduce it independently (optionally via `replay.py` — exact-byte replay of a captured raw-HTTP transcript, for browser-channel / complex authed flows that are hard to re-derive; stale-credential-aware). Findings
   that can't be reproduced are downgraded to "lead" and kept out of the report.
5. **Reporting.** `reporter` turns surviving, reproduced findings into a
   CVSS-scored report — one evidence block per finding. It MUST write the file
   (`report.md`), not return it as text.
6. **QA gate (before delivery).** `qa-auditor` runs the gate in `qa-gate.md`
   against the written report — deliverable integrity, finding completeness,
   severity discipline, CVE corroboration, redaction, coverage, RoE. `BLOCK` →
   fix and re-run. A report is not final/client-ready until the gate returns
   `PASS`. (Skill: `/pentest-qa`.)

## Orchestration notes

- **Mixed-model by design.** Mechanical, tool-driven stages (recon, the active
  finders, reporting) run on a cheaper model (`sonnet`); the judgment-heavy
  review stages (`verifier`, `qa-auditor`) run on a stronger model (`opus`),
  set in each agent's frontmatter. Re-running the whole pipeline on a bigger
  model mostly wastes spend — the value is on verify/QA. To A/B it, re-run
  only the verify stage on the larger model (Workflow resume caches the finders).

- **Parallel finders, serial truth.** Run recon/web/cloud concurrently; gate
  everything through the verifier before it counts.
- **Diversity beats redundancy.** When verifying, give checkers distinct lenses
  (does-it-reproduce / is-it-actually-exploitable / is-it-already-known) rather
  than three identical re-checks.
- **Default to the smaller blast radius.** Prefer a read that proves the issue
  over a write that demonstrates impact. One PoC, then stop.
- **Everything lands under** `engagements/<engagement.name>/` — raw evidence in
  `evidence/`, the report at `report.md`. Never write findings outside it.

## Standard coverage (for client-grade engagements)

To be viable for any client, the engagement must map to recognized methodologies
and speak the client's language. Agree the depth with the client up front and
track coverage honestly (a skipped test case is a stated gap, not silent — see
`tradecraft-doctrine.md` §3).

| Layer | Frameworks the kit aligns to |
|---|---|
| Process | PTES, NIST SP 800-115, OSSTMM — the overall engagement lifecycle |
| Web | OWASP **WSTG** (test cases), OWASP **Top 10** (taxonomy), OWASP **ASVS** (verification depth/level) |
| API | OWASP **API Security Top 10** |
| Cloud / IAM | **CIS Benchmarks**, provider well-architected security pillars, **MITRE ATT&CK** (Cloud) |
| Findings taxonomy | **CWE** (class) + **CVSS 3.1** (severity) + **MITRE ATT&CK** (attacker-technique narrative) |
| Compliance (optional, per client) | map findings to **PCI-DSS / SOC 2 / ISO 27001 / HIPAA** control IDs on request |

The deliverable should state which WSTG/ASVS coverage was attempted and the ASVS
level targeted, so "tested and clean" is backed by a coverage matrix, not a vibe.

## Vuln-class dispatch — symptom → suspect class → first probe

Seed leads in phases 2–3 by pattern-matching the recon surface. Each row is the
*cheapest* probe that splits "real vs benign" (feeds `engagement-loop.md` step 3).
The dispatch is a starting point, not a checklist — follow the redirects.

| Observed | Suspect class | Cheapest first probe |
|---|---|---|
| Numeric/UUID object ids in URLs/bodies | IDOR / BOLA | swap id to another user's resource **as the low-priv identity** |
| `org`/`tenant`/`account` id in requests | Tenant-isolation break | cross-tenant id substitution |
| Reflected param in response | XSS / open redirect | check execution context + output encoding |
| `redirect`/`next`/`return`/`url` param | Open redirect / SSRF | point off-origin, then at an internal host |
| Server-fetched `url`/`callback`/`webhook`/`img` | SSRF | `ssrf_probe.py` — OOB callback confirms the fetch (LEAD) → internal/metadata-reach ladder; metadata CONTENT reflected (signal absent from baseline + not in the injected URL) = CONFIRMED; GCP/Azure IMDS + loopback are structurally unconfirmable black-box (noted, not "clean") |
| Error leaks SQL/stack/path | Injection / info disclosure | boolean- then time-based control probe |
| JSON-bodied login/query (MongoDB/CouchDB/Firebase) | NoSQL injection (CWE-943) | `nosql_probe.py` — `$ne`/`$gt`/`$regex`/`$where` boolean + `$where` timing (≥2.5s) |
| Shell-spawning param (ping/dns/convert/preview/file op) | OS command injection (CWE-78) | `cmd_inject.py` — `sleep` timing + echo marker across shell separators |
| Reflected `{{…}}`/`${…}`/`<%=…%>` | SSTI (CWE-1336) | `ssti_probe.py` — differential `7*7=49` AND control `8*8=64` (literal consumed, not in baseline) across 8 engine syntaxes = SSTI LEAD |
| JWT / session token present | Auth/session flaws | `alg:none`, signature strip, claim tamper |
| "Sign in with Google/Apple/GitHub" / OAuth `authorize` endpoint | OAuth grant-flow misconfig (ATO) | `oauth_probe.py` — `redirect_uri` parser-discrepancy (code issued for an attacker origin?), `state`, `PKCE` |
| Role/`isAdmin`/permission field in a request body | Priv-esc / mass assignment | add/elevate the field and replay |
| File upload or path-like param | Path traversal / unrestricted upload | `../` traversal + content-type/extension bypass |
| Path/include param on a PHP/Node app (`file`/`page`/`template`/`include`) | LFI/RFI (CWE-22/73/98) | `lfi_probe.py` — `php://filter` base64 source-disclosure + `../`/`data://`/`file://` wrappers; baseline-guarded |
| GraphQL endpoint | Introspection / BOLA | `graphql_probe.py` — introspect schema, enumerate types/queries/mutations, then object-level access |
| Cloud storage URL (s3/gcs/blob/r2) | Public bucket / object | anonymous list/get |
| Generic `Server:`/`X-Powered-By:` banner; server framework unclear | Server-framework fingerprint | `framework_fingerprint.py` — distinctive headers/cookies/routes/error-sigs (Spring/Django/Laravel/Struts/…) to drive CVE + `ssti`/`deser` targeting |
| Serialized blob in a cookie/body/value (Java/PHP/pickle/.NET ViewState/Ruby/node-serialize) | Insecure deserialization (CWE-502) | `deser_detect.py` — sink detection (exploitation needs a gadget chain; LEAD) |
| Disclosed component/plugin version (WP) | Known-CVE (version match) | `cve_lookup.py` (OSV) → if `coverage_gap` for WP, run `Workflow({name:'plugin_cve_research', args:{plugins:[...]}})` — web-search NVD/Wordfence/Patchstack/WPScan for each plugin+version |
| Concurrent state-change (coupon/balance/quota/role) | Race / TOCTOU | `race_probe.py` — concurrent burst vs serial; concurrent effects > max-expected = race (CWE-362) |
| Node app + JSON merge/defaults endpoint | Prototype pollution (SSPP) | `proto_pollute.py` — `__proto__`/`constructor.prototype` + re-read a decision endpoint (CWE-1321) |
| Cache-Control: public + path variations | Web cache deception/poisoning | `cache_probe.py` — path-confusion (`/path;.css`); unkeyed-input poison (poison-then-clean-fetch) |
| `ws://` / Socket.IO / SSE endpoint | WebSocket stateful surface | `websocket_probe.py` — handshake auth (Origin/cookie); message-level IDOR (2-session) |
| Input stored, rendered in ANOTHER context | Second-order injection | `second_order.py` — inject canary, grep the render surface (admin/export/inbox) |
| Sensitive one-click action + no XFO | Clickjacking | `clickjack_probe.py` — frameability + PoC builder |
| State-changing POST (email/password/permission/transfer) | CSRF (CWE-352) | `csrf_probe.py` — control (with-token) vs strip-token vs tamper vs wrong-Origin; a stripped token still accepted = CSRF |
| WAF blocks a payload | WAF evasion | `waf_bypass.py` — variant battery (encoding/case/comment/HPP) |
| Reflected/stored input, needs VICTIM proof | XSS (end-to-end) | `xss_payloads.py` + `oob.py` — OOB-exfil payload; render in browser → callback = confirmed execution |
| Reflected param, context + encoding check | XSS (reflection-grade, CWE-79) | `xss_scan.py` — reflection + landing context (HTML/attr/script) + encoding-neutralization; DOM-XSS via `browser_probe.py` |
| CSP header present but bypassable (`unsafe-inline`, `*`, JSONP/CDN allowlist, nonce + `unsafe-inline`) | Weak CSP (XSS viable, CWE-693) | `csp_probe.py` — directive analysis (the difference between "hardening OK" and "XSS exploitable here") |
| GraphQL endpoint (beyond introspection) | Depth/cost, batching, field-suggestion | `graphql_adv.py` — `--depth` (cost), `--batch` (authz bypass), `--suggest` (schema brute) |
| `/openapi.json` / `/swagger.json` exposed | API spec → per-operation fuzz | `openapi_probe.py` — type-confusion / enum-bypass / missing-required / extra-field per operation, baseline-diffed (LEAD) |
| Multi-step flow (cart/coupon/checkout/payment) | Business-logic / workflow abuse | `flow_probe.py` — skip-step, field-tamper (qty/price/coupon), reorder + diff |
| Edge openresty/nginx + H2 default | HTTP/2 request smuggling | `h2_smuggle.py` (h2c, H2.CL timing) + `smuggle_probe.py` (H1 CL.TE/TE.CL) |
| JWT in Authorization header | JWT attacks | `jwt_probe.py` — analyzer (alg:none/RS→HS/kid surfaces) + `--crack` (offline HS weak-secret) + `--attack-url` active forge (alg:none accept, claim-escalation, RS→HS key-confusion, cracked-secret forge), each forged variant paired with a wrong-sig control so acceptance is decisive (CWE-347) |
| Cross-origin fetch + reflected ACAO + credentials | CORS misconfiguration | `cors_probe.py` — reflected arbitrary Origin + Allow-Credentials (CWE-942) |
| `Host:` header reflected / response splits / `X-HTTP-Method-Override` / header-borne redirect | Host-header injection / CRLF / method-override / open-redirect | `header_probe.py` — host-header reflection, CRLF/response-splitting, method-override, off-origin redirect (each with a control; positives are LEADS) |
| SPA with deep/minified JS bundles | Hidden/unlinked endpoints | `js_routes.py` — fetch/axios/route-table extraction |
| Endpoint suspected of hidden params | Parameter discovery | `param_probe.py` — ~100 common params, baseline-diff (length/status/reflection) |
| Dangling-CNAME subdomain | Subdomain takeover | enumerate with `subdomain_enum.py` (passive multi-source + brute), then `takeover_probe.py` — fingerprint DB (S3/GitHub/Heroku/Azure/Vercel) |
| Third-party scripts loaded cross-origin | Supply-chain / missing SRI | `sri_check.py` — cross-origin script integrity + cookie-access |
| Blind SSRF/XXE/smuggling (needs callback) | OOB confirmation | `oob.py` collaborator (local + Interactsh) + `xxe_probe.py` |
| SOAP/WSDL endpoint (`?wsdl`, `application/soap+xml`/`text/xml`) | WSDL exposure / XXE via SOAP / SQLi via params | `soap_probe.py` — discover+parse the WSDL (operation/param contract = an info lead), then per-operation XXE (reflected `file:///` + OOB, CWE-611) + SQLi (error/boolean, CWE-89), each baseline + malformed-control guarded |
| Ajax/REST action with a signature-gated query param | SQLi behind an integrity gate | reachability first (is the action callable unauth?), then probe params that bypass the signature check (alternate query params, sibling actions, non-query params like pagination/offset); boolean/time/**error-based** SQLi (`extractvalue`/`updatexml` — WAF-clean when `SLEEP` is keyword-blocked) |
| Integrity-gated query param (HMAC signature) | Signature acquire / mint / juggling | harvest a valid (query,sig) pair from a rendered page; self-mint via an open write endpoint; type-juggle the gate (empty/`0`/`[]=`/`null`); reverse the HMAC offline if a (query,sig) pair is obtained |
| Multipart upload field (`enctype=multipart/form-data`, `<input type=file>`) | Unrestricted upload / upload-to-RCE / stored-XSS-via-SVG (WSTG-BUSL-09) | `upload_probe.py` — benign-GIF control + bare `.php` allowlist probe, then double-ext / null-byte / alt-ext (`.phtml`/`.phar`/`.php5`) / content-type-mismatch / polyglot-GIF / `.htaccess` / SVG battery; ACCEPTANCE≠EXECUTION (lead until fired on a lab), SVG served as `image/svg+xml` = stored-XSS primitive; ACTIVE → `mutation_testing: approved` |
| Login / OTP / password-reset / 2FA / state-changing endpoint | Missing rate limit / brute surface (API4:2023) | `rate_limit_test.py` — burst N requests, detect 429 / `Retry-After` / lockout / body-marker / latency-spike; absence on a SENSITIVE endpoint = brute-force / credential-stuffing / OTP-bombing lead (agent judges severity); a DETECTOR not a stuffer (no password lists); an authed per-account throttle is a `coverage_gap`, not "clean" |

**Chain-synthesis:** once the finders + verifier have confirmed primitives, the **`exploiter`** agent
(post-verifier, pre-reporter, under `mutation_testing: approved`) composes them into end-to-end
attack chains at their chain severity — e.g. JWT-forge→ATO, SSRF→metadata reach, gadget pingback,
gated SQLi extraction, IDOR scale. See `.claude/agents/exploiter.md`.

## Edge-WAF channel routing (JS proof-of-work + per-IP graylist)

Some edges (Imunify360, Cloudflare "checking your browser") gate the app behind a **JS
proof-of-work challenge** AND **per-IP adaptive graylisting**. Both blind every
urllib/curl/nuclei client — even on a fresh Tor exit — producing uniform challenge pages
(the "WAF/challenge shell" false-positive class in `pitfalls.md`). The channel that
actually reaches the app:

- **Browser solves the PoW.** A real top-level navigation (Playwright/Chromium) executes
  the challenge JS like a real client and clears it; same-origin `fetch()` from the warm
  tab then reaches `wp-json/*` and `admin-ajax` carrying the edge-clearance cookie.
  Re-test ANY path-probe / "exposure" / injection through the browser before believing it.
- **IP rotation beats the graylist.** A burst trips the per-IP graylist (sustained
  TCP-SYN drop, HTTP 000). Route the headless browser through a **Tor SOCKS**
  (`proxy: socks5://127.0.0.1:9050`) — a fresh exit (`SIGNAL NEWNYM` on the control port)
  restores reachability. Combine: **headless-Chromium-through-Tor** is the channel that
  beats both the PoW and the graylist. (Login pages are often graylisted harder than the
  public site — a wp-login brute-force from a Tor exit is typically login-page-blocked; a
  residential proxy is the realistic attacker egress for that path.)
- **Kit egress tooling (no Tor/provisioned proxy?).** `proxy_rotate.py <target>` sources
  free public HTTP proxies (TheSpeedX/PROXY-List, ProxyScrape), tests them in parallel, and
  returns ones that reach the target's edge; pass one to `browser_probe.py --proxy http://ip:port`
  (or any Playwright `proxy={"server":...}`). The proxy beats the graylist; the browser beats
  the PoW. **RoE: free proxies are unknown operators — recon only, never route
  credentials/tokens/PII through them.**

`waf_detect.py` routes the channel FIRST; on `js-challenge`, do not trust non-browser
results. `browser_probe.py` is the deterministic browser-channel tool (DOM/forms/network/
headers/screenshot in a real headless Chromium) — re-run it on every urllib-blind positive.

## The black-box ceiling

A black-box app test proves what it *found*, not that *no vulnerability exists*. Even an
exhaustively-tested app surface (every in-range CVE, every standard class, the full
REST/ajax surface) being clean does **not** mean the site is unbreachable — a real attacker
who finds the app locked shifts to the **perimeter**: phish a known user (username
enumeration + a spoofable domain), take the **hosting** (shared-box cPanel / edge CVEs), or
poison the **supply chain** (no-SRI third-party scripts / malicious plugin updates). State
those layers + the authenticated surface as **coverage gaps** in the report — they are
where real breaches of well-defended sites actually happen, and most sit outside a
black-box app test's reach (social engineering / shared infra / third parties / time). "No
finding" is scoped to the methodology + known-vuln coverage at the time of testing, not a guarantee.

See `tradecraft-doctrine.md` (how to test), `engagement-loop.md` (the per-lead
loop), `pitfalls.md` (false-positive catalog), `rules-of-engagement.md` (hard
limits), and `evidence-standard.md` (what counts as a finding + dispositions).
