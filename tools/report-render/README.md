# Report renderer

`findings.json` is the **single source of truth**; this renderer generates the
deliverable from it — `report.md` (human) + `report.html` (**dark**, default) via
`--all`; the light/print theme (`report-light.html`) is **opt-in** via
`--theme light` — so markdown and HTML can never drift. HTML is **fully
standalone** — CSS is inlined **and the referenced evidence is embedded inline**
(text artifacts in collapsible blocks, screenshots as base64), so a client who
receives only `report.html` has the complete evidence with no loose files. Per-
finding evidence bullets link to the embedded artifact in the appendix. Embedded
text is **redaction-neutralized** on the way in (same chokepoint that refuses to
render credential material); oversized artifacts are truncated/noted, never
silently dropped. Use `--no-embed-evidence` for a lean report whose evidence ships
separately. The dark theme keeps its background in PDF via a `@media print` block.
Dark-glass design system, re-keyed to pentest **severity**.

## Usage

```bash
# RECOMMENDED — generate everything from findings.json
python tools/report-render/render_report.py engagements/<name>/findings.json --all
#   → report.md + report.html (dark)   [light/print is opt-in: --theme light]

# Single outputs
python tools/report-render/render_report.py engagements/<name>/findings.json            # report.html (dark, evidence embedded)
python tools/report-render/render_report.py engagements/<name>/findings.json --md        # report.md only
python tools/report-render/render_report.py engagements/<name>/findings.json --no-embed-evidence   # reference index instead of inline evidence
python tools/report-render/render_report.py engagements/<name>/findings.json out.html --theme light

# PDF (headless, no extra deps — uses installed Edge/Chrome)
"<edge-or-chrome>" --headless=new --disable-gpu --no-pdf-header-footer \
    --print-to-pdf="engagements/<name>/report-light.pdf" \
    "file:///<abs>/engagements/<name>/report-light.html"
```

To revise a report, edit `findings.json` and re-run `--all` — never hand-edit the
generated files. Theme precedence: `--theme` flag → `engagement.theme` → `dark`.

## Files
- `render_report.py` — renderer (stdlib only; documents the `findings.json` schema in its header).
- `export.py` — converts findings.json → **SARIF 2.1.0 / Jira-CSV / DefectDojo** for vuln-management ingestion (redaction chokepoint). `python export.py <findings.json> [--formats sarif,csv,defectdojo]`.
- `report.css` — dark-glass theme (default; striking on screen).
- `report-light.css` — light, print/PDF-friendly theme (white bg, page-break-aware, `print-color-adjust: exact`).

## findings.json
The `reporter` agent emits it alongside `report.md`. Severities are
`critical|high|medium|low|info`; structure: `engagement`, `overall_risk`,
`risk_tier`, `summary`, `counts`, `findings[]`, `informational[]`, `leads[]`,
`evidence_index[]`. See the schema block atop `render_report.py` and
`engagements/<slug>/findings.json` for a worked example.

### Standards mapping & coverage (report section 4)
For a client-grade, standards-aligned deliverable, findings.json may also carry:
- **Per finding:** `owasp` (OWASP Top 10), `wstg` (WSTG test ID), `attack` (MITRE
  ATT&CK) → rendered as a per-finding **Standards:** line; plus `validation_status`
  (verified/available/unconfirmed → "Confidence").
- **Engagement level:** `asvs_level`; `coverage: [{area,status,notes}]` (the
  OWASP-WSTG / ASVS / API **coverage matrix** — Tested/Partial/Not-tested, so
  "tested & clean" is backed by a matrix, not a vibe); `limitations: [..]` (honest
  coverage gaps — a skipped test is a STATED gap); and `compliance` (PCI/SOC2/ISO).
  All optional; rendered together as report **section 4 "Standards coverage &
  limitations."**
- **Engagement branding:** `engagement.brand` (text name, default `Redan`)
  + optional `engagement.logo` (a path relative to the engagement dir to a
  PNG/SVG/JPG) — the logo is base64-inlined into the report header's brand mark
  (replacing the first-letter monogram). No new dependency.
