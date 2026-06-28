<h1 align="center"><img src="logo.svg" alt="Redan" height="76"></h1>

<p align="center"><em>A multi-agent web pentest toolkit for Claude Code — every finding is independently verified and QA-gated.</em></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/core-stdlib--only-success.svg" alt="Core: stdlib-only">
</p>

> ⚠️ **Authorized testing only.** For assets you own or are explicitly authorized
> to test — own infrastructure, in-scope bug-bounty, CTF/lab, or a signed
> engagement. The `scope.yaml` gate and scope-gate hook hard-deny out-of-scope
> hosts, and every agent is bound to rules of engagement that override task
> prompts. Unauthorized testing is illegal.

Redan runs a black-box web/API assessment as a team of agents: `recon` /
`web-tester` / `auth-tester` / `cloud-iam` (finders) → an independent **verifier**
that tries to refute every candidate → an **exploiter** that chains confirmed
issues into attack paths → a **reporter** → a **QA gate**. It ships a
CVSS-scored report in which every finding traces to a reproduction. It runs inside
[Claude Code](https://docs.claude.com/en/docs/claude-code/overview); the 67
deterministic tools are stdlib Python (Playwright is optional, for the browser channel).

Unlike a scanner that trusts its own output, Redan verifies its own findings: a
separate agent tries to refute each one before it counts, and a separate QA gate
blocks the report until it passes. Most tools produce hits; this produces verified
findings.

## Quickstart

1. **Open the repo in [Claude Code](https://docs.claude.com/en/docs/claude-code/overview)** — agents, skills, and hooks auto-register.
2. `/pentest-init <slug>` — scaffolds `engagements/<slug>/` (`scope.yaml` + `authorization.md`). No active testing until a signed basis is recorded.
3. `cp engagements/<slug>/scope.yaml scope.yaml` — activate the engagement.
4. `/pentest <target>` — recon → active finders (parallel) → `verifier` → (optional) `exploiter` → `reporter`.
5. `/pentest-report` — `findings.json` → `report.md` + standalone HTML + PDF.
6. `/pentest-qa` — a report isn't final until the QA gate returns `PASS`.

## Prerequisites

- **[Claude Code](https://docs.claude.com/en/docs/claude-code/overview)** (the CLI).
- **Python 3.10+** — the 67 tools are stdlib-only.
- **Playwright** *(only for the browser-channel agents + `browser_probe.py`; the stdlib tools run without it)*:
  ```sh
  pip install playwright && playwright install chromium
  ```

<details>
<summary><b>Optional depth tools</b></summary>

- **nuclei** — thousands of vulnerability templates; `python tools/external/bootstrap.py`.
- **sqlmap** — SQLi confirmation; `bootstrap.py --sqlmap`.
- **Tor** (`socks5://127.0.0.1:9050`) — for per-IP-graylisted edges; see [`methodology.md`](.claude/rules/methodology.md) → "Edge-WAF channel routing".

</details>

## What's in it

```
scope.yaml -> /pentest -> recon · web-tester · auth-tester · cloud-iam
                       -> verifier -> exploiter -> reporter -> qa-auditor -> report
  gate        sonnet finders (parallel)  opus refute  opus chains  PASS/BLOCK
```

- **8 agents** (`.claude/agents/`) — finders → `verifier` (refute) → `exploiter` (chains) → `reporter` → `qa-auditor`. Mixed-model: `sonnet` finders, `opus` judgment.
- **67 stdlib modules** (`tools/checks/`, stdlib-only, JSON) — recon, active testing (injection, XSS, SSRF, access control, request smuggling, file upload, SOAP/XXE, rate limiting, JWT, …), authenticated testing, and reporting. Full catalog: [`tools/checks/README.md`](tools/checks/README.md).
- **Chain exploitation** — the `exploiter` combines confirmed issues into full attack chains (JWT-forge→account takeover, SSRF→internal metadata, IDOR at scale).
- **Reporting** — `findings.json` → `report.md` + standalone HTML (CSS + evidence inlined — one file, no loose artifacts) + PDF. Per-finding OWASP/WSTG/ATT&CK + CVSS/CWE. Export → SARIF / Jira / DefectDojo.
- **QA gate** — mechanical pre-flight (`finding_schema` + `redact`) → 5-lens panel → `PASS`/`BLOCK`.

<details>
<summary><b>Sample finding</b> — what a confirmed finding looks like in the report</summary>

> **F-01 — IDOR on /api/orders/{id}** &nbsp; `CRITICAL · 9.1` &nbsp; CWE-639 · WSTG-ATHZ-04
>
> **Location:** `GET /api/orders/{id}` &nbsp;·&nbsp; **CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` — 9.1
>
> The endpoint authorizes by session but doesn't scope the object id to the caller's tenant; a low-priv session reads another tenant's order (PII).
>
> **Reproduction**
> 1. Authenticate as a low-priv user (tenant A).
> 2. `GET /api/orders/1002` (tenant B's order) → `200 OK` with tenant B's detail.
> 3. Control: `GET /api/orders/1001` (your own) also 200; a properly-scoped endpoint 403s the foreign id.
>
> **Remediation:** scope every object lookup to the caller's tenant at the data-access layer; add an automated authz test to CI.
> **Verification:** independently reproduced from a fresh session; control succeeds, foreign id 403s after a partial fix.

</details>

## The gate — `scope.yaml`

The single source of authorization: `in_scope`, `out_of_scope` (+ patterns, hard-denied), `rules_of_engagement`, `mutation_testing`, `production`. The scope-gate hook (PreToolUse) hard-denies active tool calls reaching an out-of-scope host. **It's a guardrail, not a sandbox** — the real control is only testing targets you're permitted to test.

### Authenticated testing (optional)

When test accounts are provisioned, credentials stay **out of the repo** under `$PENTEST_AUTH_HOME` (default `~/.redan/auth/<slug>/`). The `auth-tester` reads roles from there — never from the repo tree. Read-only by default (the mutation-gate denies authenticated writes unless `mutation_testing: approved`).

## Posture

Built for real engagements — own assets, bug-bounty, CTF/lab, or signed client work. The methodology maps to OWASP WSTG/ASVS, OWASP API Top 10, PTES, NIST SP 800-115, CWE/CVSS, MITRE ATT&CK. It's a serious tool, not a complete one: **out of scope by choice** (network / Active Directory / mobile / white-box SAST), and a black-box test always has blind spots — see Coverage honesty.

## Coverage honesty

A black-box test proves what it *found*, not that *no vulnerability exists*. A real attacker who finds the app locked shifts to the perimeter (phishing, shared-hosting CVEs, supply chain). Redan reports those layers and the authenticated surface as stated coverage gaps, never as silently "clean." See [`methodology.md`](.claude/rules/methodology.md) ("The black-box ceiling").

## Layout

```
.claude/{agents,rules,skills,workflows,hooks}/   the ensemble + doctrine + orchestration
tools/checks/                                     67 stdlib modules (stdlib-only, JSON)
tools/report-render/                              findings.json -> report.md/html + SARIF/Jira/DefectDojo
tools/external/                                   nuclei + sqlmap binaries (gitignored, bootstrapped)
engagements/_template/                            per-engagement scaffold (copied by /pentest-init)
scope.yaml                                        active engagement (gitignored — switch per engagement)
CLAUDE.md                                         full project instructions
```
`engagements/<name>/` (real target data) is gitignored except the template.

## Documentation

- **[CLAUDE.md](CLAUDE.md)** — architecture, conventions, current state.
- **[.claude/rules/](.claude/rules/)** — the doctrine: tradecraft, evidence standard, methodology, pitfalls, QA gate, rules of engagement.
- **[tools/checks/README.md](tools/checks/README.md)** — the 67-tool catalog.

## Running on other Anthropic-compatible backends

Redan runs on any Anthropic-compatible endpoint — set the env vars below, then launch `claude`. No vendor lock-in; bring your own endpoint.

<details>
<summary><b>Example env</b></summary>

```sh
export ANTHROPIC_BASE_URL=<your-endpoint>
export ANTHROPIC_AUTH_TOKEN=<key>            # or ANTHROPIC_API_KEY
export ANTHROPIC_DEFAULT_OPUS_MODEL=<model>
export ANTHROPIC_DEFAULT_SONNET_MODEL=<model>
export ANTHROPIC_DEFAULT_HAIKU_MODEL=<model>
claude
```
</details>

## License

MIT — see [LICENSE](LICENSE). Authorized use only.
