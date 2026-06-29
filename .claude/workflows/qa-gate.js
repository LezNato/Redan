export const meta = {
  name: 'qa-gate',
  description: 'Pre-delivery QA gate (.claude/rules/qa-gate.md): parallel adversarial lenses audit a COMPLETED engagement report -> PASS / BLOCK. Defensive report quality-assurance. args: {engagement: "<slug>"} (default reads engagements/<slug>/).',
  phases: [
    { title: 'Preflight', detail: 'mechanical validators (finding_schema + redact) -- short-circuit BLOCK if they fail' },
    { title: 'Audit', detail: 'parallel QA lenses, one per qa-gate.md dimension' },
    { title: 'Verdict', detail: 'synthesize PASS/BLOCK + blocking issues' },
  ],
}

// --- parameterized by args.engagement (the engagements/<slug>/ folder) ---
// Robust to harness args-dropping: if args.engagement is missing, self-discover the active
// engagement from scope.yaml (the active-engagement gate) via a one-shot agent. Workflow scripts
// have no filesystem access, so an agent reads it. This keeps /pentest-qa working even when the
// Workflow({name|scriptPath, args}) form fails to inject the args global.
let ENG = args && args.engagement
if (!ENG) {
  log('args.engagement not received (harness args-dropping?) -- self-discovering from scope.yaml')
  const SCOPE_SCHEMA = { type:'object', additionalProperties:false, properties:{ engagement:{type:'string'} }, required:['engagement'] }
  const found = await agent(
    'Read scope.yaml in the repository root (the active-engagement gate). Under the top-level "engagement:" block there is a "name:" field -- return that slug. If scope.yaml is unreadable or has no engagement.name, return engagement="". Return {engagement}.',
    { label:'scope-read', schema: SCOPE_SCHEMA }).catch(() => null)
  ENG = found && found.engagement
}
if (!ENG) { return { error: 'no engagement slug. Pass args.engagement = "<slug>", or ensure scope.yaml has engagement.name (the self-discovery fallback).' } }
const DIR = `engagements/${ENG}`

const CTX = `You are a QA AUDITOR running the pre-delivery quality gate (.claude/rules/qa-gate.md) on a COMPLETED penetration-test report before it is treated as client-deliverable. This is DEFENSIVE report quality-assurance -- you are checking a FINISHED report for accuracy, completeness, and discipline; you are NOT testing a live target or exploiting anything. Read the deliverable at ${DIR}/{findings.json, report.md, evidence/}. Be adversarial about QUALITY: a single real defect is a BLOCK. Cite specifics (finding id, line, file).`

const SCHEMA = { type:'object', properties:{
  dimension:{type:'string'},
  verdict:{type:'string', enum:['pass','block']},
  issues:{type:'array', items:{type:'object', properties:{
    severity:{type:'string', enum:['block','warn','note']}, finding:{type:'string'}, detail:{type:'string'} }, required:['severity','detail']}},
  notes:{type:'string'} }, required:['dimension','verdict'] }

const LENSES = [
  {k:'integrity', p:`DELIVERABLE INTEGRITY + FINDING COMPLETENESS (qa-gate items 1-2). Run: python tools/checks/finding_schema.py ${DIR}/findings.json . Confirm report.md/report.html exist; every confirmed finding has location, reproduction, evidence artifact (verify the referenced files exist under ${DIR}/evidence/ with ls/Glob), CVSS vector+score, CWE, concrete impact, remediation, verification note. Any finding lacking a reproduction must be a Lead, not a Finding.`},
  {k:'severity', p:'SEVERITY DISCIPLINE + NUMBER INTEGRITY (qa-gate items 3, 4b). Confirm no severity is inflated ABOVE its CVSS band (down-rating is allowed); exec-summary counts EQUAL the actual findings by severity; each finding carries validation_status and a non-verified High is justified; a component finding rated below its advisory CVSS (e.g. retained as a labeled component score) is explained. Every CVSS/CWE/count traces to an evidence source.'},
  {k:'cve-corrob', p:'EXTERNAL-CLAIM / CVE CORROBORATION (qa-gate item 4). For each CVE id cited: WebSearch for >=2 authoritative sources (NVD / GitHub Advisory / WPScan / vendor) and note corroboration. Every CVE that postdates the tester knowledge cutoff MUST be FLAGGED in the report for WPScan/NVD confirmation -- verify the report does so. Confirm component findings state exploitation was NOT performed where true (no implied live exploit a version-match did not demonstrate).'},
  {k:'disposition-coverage', p:'DISPOSITION HYGIENE + COVERAGE HONESTY (qa-gate items 5, 7). Canonical dispositions only; no refuted/duplicate/out-of-scope items sitting in Findings; any downgrade REPLACED the prior claim (no stale "High" left inline, exec counts fixed). Confirm the report STATES its coverage limitations honestly (what was not tested + why) -- a skipped test is a stated gap, not a clean result. If a standards coverage matrix (section 4) is present, verify it does not claim Tested where coverage was only Partial.'},
  {k:'redaction-roe', p:`REDACTION + RoE (qa-gate items 6, 8). Run: python tools/checks/redact.py scan ${DIR} (must exit 0 / clean = no Authorization/Cookie/Set-Cookie/JWT/api_key/password material anywhere in the tree). Confirm the report RoE narrative is truthful: non-destructive unless active exploitation was authorized (scope mutation_testing approved); any state-changing action was a no-op/minimal proof; on real user PII only minimal proof was taken. Flag any place the report implies an exploit or impact it did not actually demonstrate.`},
]

// --- mechanical pre-flight: the deterministic validators gate the expensive LLM panel.
// finding_schema.py now catches structure / band-inflation / count-drift / DANGLING REFS /
// summary-count integrity; redact.py catches credential leaks. If either fails, BLOCK on ONE
// single sonnet agent instead of spending the 5-lens Opus panel (those defects are deterministic).
phase('Preflight')
const PRE = { type:'object', properties:{
  schema_valid:{type:'boolean'}, schema_errors:{type:'array', items:{type:'string'}},
  redact_clean:{type:'boolean'}, redact_detail:{type:'string'} }, required:['schema_valid','redact_clean'] }
const pre = await agent(
  `Run EXACTLY these two commands and report their results -- do nothing else, do NOT test any live target:\n` +
  `1) python tools/checks/finding_schema.py ${DIR}/findings.json  (read the JSON 'valid' + 'errors')\n` +
  `2) python tools/checks/redact.py scan ${DIR}  (redact_clean = true iff exit code 0)\n` +
  `Return {schema_valid, schema_errors, redact_clean, redact_detail}.`,
  { label:'qa:preflight', phase:'Preflight', agentType:'qa-auditor', model: 'sonnet', schema: PRE })
if (pre && (!pre.schema_valid || !pre.redact_clean)) {
  log('mechanical pre-flight FAILED -- blocking before the LLM panel (saves the Opus panel)')
  return { engagement: ENG, gate: 'BLOCK', preflight: pre,
    blocking_issues: [
      ...(pre.schema_valid ? [] : (pre.schema_errors || ['finding_schema invalid']).map(e => ({dimension:'mechanical: finding_schema', detail:e}))),
      ...(pre.redact_clean ? [] : [{dimension:'mechanical: redaction', detail: pre.redact_detail || 'redact scan found credential material'}]) ],
    note: 'Mechanical validators failed -- fix and re-run; the LLM panel was skipped to save tokens.' }
}

phase('Audit')
log(`Mechanical pre-flight clean; running 5 adversarial lenses on engagements/${ENG}`)
const verdicts = await parallel(LENSES.map(l => () =>
  agent(CTX + '\n\nDIMENSION: ' + l.p + '\n\nReturn {dimension, verdict (pass/block), issues[], notes}.',
    { label:'qa:'+l.k, phase:'Audit', agentType:'qa-auditor', model:'opus', schema: SCHEMA }).catch(() => null)))

const real = verdicts.filter(Boolean)
const blockers = real.flatMap(v => (v.issues||[]).filter(i => i.severity==='block').map(i => ({dimension:v.dimension, ...i})))
const lensBlocked = real.some(v => v.verdict==='block') || blockers.length > 0

phase('Verdict')
const ARB = { type:'object', properties:{
  gate:{type:'string', enum:['pass','block']}, summary:{type:'string'},
  blocking_issues:{type:'array', items:{type:'object', properties:{
    item:{type:'string'}, detail:{type:'string'}, remediation:{type:'string'} }}} }, required:['gate'] }
const arb = await agent(CTX + '\n\nYou are the QA gate ARBITER. Per-dimension lens verdicts:\n' +
  JSON.stringify(real, null, 1).slice(0, 9000) +
  '\n\nReturn the OVERALL gate verdict: PASS only if every dimension passed with no block-severity issue; otherwise BLOCK. List each blocking issue tied to its qa-gate item with a one-line remediation. Do not rubber-stamp; do not invent blocks. Return {gate, summary, blocking_issues[]}.',
  { label:'qa:arbiter', phase:'Verdict', agentType:'qa-auditor', model:'opus', schema: ARB }).catch(() => null)

// The arbiter's verdict COUNTS: the gate BLOCKs if the mechanical lens aggregation OR the
// arbiter says block (defense in depth -- the arbiter can escalate a cross-lens issue no single
// lens marked 'block'; it can never rubber-stamp a lens block up to pass).
const arbiterBlock = !!(arb && arb.gate === 'block')
const finalBlock = lensBlocked || arbiterBlock

return {
  engagement: ENG,
  gate: finalBlock ? 'BLOCK' : 'PASS',
  decided_by: lensBlocked ? 'lens-aggregation' : (arbiterBlock ? 'arbiter' : 'unanimous-pass'),
  dimensions: real.map(v => ({dimension:v.dimension, verdict:v.verdict, block_issues:(v.issues||[]).filter(i=>i.severity==='block').length})),
  blocking_issues: blockers.map(b => ({dimension:b.dimension, detail:b.detail, finding:b.finding||''})),
  arbiter: arb || { gate: 'unknown', summary: 'arbiter agent returned null (treated as non-blocking)' },
}
