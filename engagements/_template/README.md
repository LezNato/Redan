# Engagement template

`/pentest-init <slug>` copies this folder to `engagements/<slug>/` and fills it
in. This template is the only thing under `engagements/` that is committed; real
engagement folders are gitignored.

## Layout
```
engagements/<slug>/
├── authorization.md   # client intake: authorization basis, RoE, NDA, contacts, sign-off
├── scope.yaml         # machine-readable scope + RoE (the gate the tooling enforces)
├── evidence/          # raw artifacts: request/response, screenshots, transcripts (redact PII)
├── leads.md           # observed-but-unproven items (NOT findings)
├── findings.json      # structured findings — SINGLE SOURCE for the report (reporter writes this)
├── report.md          # GENERATED from findings.json — do not hand-edit
├── report.html        # GENERATED — dark theme, on-screen
├── report-light.html  # GENERATED — light theme, print
└── report-light.pdf   # exadapted from report-light.html (headless print)
```

## Workflow
1. `/pentest-init <slug>` — scaffold + capture authorization/RoE/scope. For client
   work, no testing starts until `authorization.md` §2 names a signed basis.
2. Make it active: `cp engagements/<slug>/scope.yaml scope.yaml` (the scope-gate
   hook + session banner read the repo-root copy). `/pentest-init` does this for you.
3. `/pentest <target>` — recon → testing → verification.
4. `/pentest-report` — reporter writes `findings.json`, then the renderer generates
   `report.md` + HTML (+ PDF for client delivery).
5. `/pentest-qa` — gate the report before it's treated as final.

Every **finding** in the report traces to a reproduction + an artifact in
`evidence/`. No reproduction → it stays in `leads.md`.
