# tests/ — the toolkit's own false-positive discipline, applied to itself

The kit's thesis is *every finding traces to a reproduction*. These tests hold the
**detectors** to that same bar: a fix is proven only when the tool **fires on a
true positive AND stays silent on a benign look-alike**. They are stdlib-only and
fully offline — each spins up a local `127.0.0.1` lab or tests pure functions, so
they run anywhere with no network and no secrets.

## Run

```bash
python tests/run_all.py          # doctrine self-audit + every suite (what CI runs)
python tests/test_injection_tools.py   # a single suite
```

CI: `.github/workflows/tests.yml` runs `run_all.py` on every push/PR.

## What's here

| File | Proves |
|---|---|
| `lab_server.py` | Reusable vulnerable **+ benign** lab. For each detector it serves a vulnerable endpoint (TP must fire) and a benign reflector/constant responder (FP **must** be rejected). Importable: `start_lab() -> (server, base_url)`. |
| `test_injection_tools.py` | `nosql_probe` / `cmd_inject` / `ssti_probe` / `xss_scan` emit a `lead` on the vuln endpoint and **nothing** on the benign one — the regression guard for the over-claiming bugs. |
| `test_redact.py` | `redact.py` catches every secret class (labeled + unlabeled), treats PII as advisory unless `--strict`, scans `.env`/extensionless files, and converges on re-run. |
| `test_scope_gate.py` | The scope-gate hook denies the denylist, **fails closed** on a missing scope for external hosts (while allowing infra/local), gates the request-issuing browser tools, canonicalizes obfuscated IPs, and honors the allowlist. |
| `test_export.py` | `export.py` populates Description from the canonical `description` field, includes reproduction, and **blocks** on credential material. |
| `test_tool_contract.py` | The `_result.py` output contract validates, and the disposition-emitting probes conform (`tool`/`target`/`ok`/valid `disposition`). |
| `test_run_manifest.py` | `run_manifest.py` wraps a tool run (enriched from the `_result` contract), records manual entries, and summarizes — the engagement audit trail. |
| `test_tools_smoke.py` | Every tool module (76) compiles **and** imports cleanly — the breakage net that makes the incremental `_http.py` migration safe. |
| `test_auth_idor.py` | The authenticated 4-cell IDOR oracle (`auth_request --idor`): confirms IDOR on an ownership-free endpoint and rejects it on the ownership-enforced one, with seeded roles/sessions in a temp out-of-tree `PENTEST_AUTH_HOME`. |
| `test_doctrine_lint.py` | The self-audit linter passes on the tree, **catches** a hard-`CONFIRMED` verdict, and honors the inline allow directive. |

## The doctrine linter

`tools/checks/doctrine_lint.py` is a deterministic self-audit (C1–C9): no
single-signal `CONFIRMED` verdicts (C1), redaction coverage of the QA-gate classes
(C2), resolvable rule cross-refs (C3), tool refs exist (C4), valid agent models
(C5), schema completeness (C6), **the repo passes its own `redact` scan** (C7),
**tool doc↔code drift** (C8), and **the stated module count is accurate** (C9 — so
the docs can't silently drift either). It runs first in `run_all.py` and gates CI —
so the kit can no longer silently drift from the discipline it preaches.

## Adding a detector test

1. Add a vulnerable endpoint **and** a benign look-alike to `lab_server.py`.
2. Assert the tool's `disposition` is `lead` against the vuln endpoint and is **not**
   `lead` against the benign one. A detector without both halves isn't proven.
