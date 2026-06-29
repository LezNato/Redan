# Reusable workflows

Named, parameterized multi-agent workflows the orchestrator can run by name
instead of hand-authoring a script per engagement. Invoke with the Workflow tool:

```js
Workflow({ name: 'pentest-assess', args: { target: 'https://example.com', engagement: 'acme' } })
Workflow({ name: 'qa-gate',        args: { engagement: 'acme' } })
```

| Workflow | What | args |
|---|---|---|
| `pentest-assess` | Core web pipeline: parallel vuln-class **finders** (web-tester) → independent **verify** (opus) → confirmed/refuted survivors. Hand survivors to the reporter → findings.json → `render_report.py`. | `{target, engagement, browser_channel?, areas?}` |
| `qa-gate` | Pre-delivery **QA gate** (`.claude/rules/qa-gate.md`): mechanical pre-flight (`finding_schema` + `redact`, short-circuits to BLOCK) then 5 parallel independent lenses (integrity / severity / CVE-corroboration / disposition+coverage / redaction+RoE) -> arbiter -> **PASS/BLOCK**. | `{engagement}` |
| `plugin_cve_research` | **Plugin CVE research** — systematic web research (NVD/Wordfence/Patchstack/WPScan) for a WP plugin inventory; >=2-source corroboration gate; fills the OSV WordPress-coverage gap. | `{plugins:[{slug,name,version},...]}` |
| `toolkit-consistency-audit` | **Toolkit consistency audit** — repo-wide check for engagement hardcoding, stale refs, doc-code drift. | (none — scans the repo) |

Notes:
- `browser_channel: true` routes finders through the Playwright browser for
  JS-challenge-WAF'd targets (urllib/curl get the challenge shell → false positives;
  see `pitfalls.md` "WAF/challenge shell"). The shared browser means browser-channel
  finders contend — keep that run low-concurrency / operator-paced.
- Override the default vuln-class lenses with `args.areas: [{key, prompt}, ...]`.
- These are the *generalizable* patterns. Target-specific runs (a particular
  engagement's bespoke hunt) stay as session-transient scripts — only the reusable
  pattern is committed here.
- **Known limitation:** heavy *offensive* prompts (active exploitation: forge/inject/
  exploit) can be refused by the model-provider's API-level cybersecurity safety
  filter; legitimate authorized engagements that need full depth require the
  cyber-use-case exemption. Defensive/QA framing (e.g. `qa-gate`) is unaffected.
