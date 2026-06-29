export const meta = {
  name: 'toolkit-consistency-audit',
  description: 'Audit the entire toolkit for project-agnostic consistency -- no engagement-specific hardcoding, stale refs, doc-code drift',
  phases: [
    { title: 'Audit', detail: '6 parallel lenses scan the whole repo' },
    { title: 'Synthesize', detail: 'prioritized fix list + consistency verdict' },
  ],
}

const SCOPE = [
  'Audit the ENTIRE Redan toolkit for PROJECT-AGNOSTIC CONSISTENCY. The toolkit must work for ANY target.',
  'No engagement-specific hardcoding, no stale references, no broken cross-refs, no doc/code drift.',
  'Scan everything EXCEPT gitignored dirs (engagements/* and .lab/*):',
  'CLAUDE.md, .claude/rules/*.md (7 files), .claude/agents/*.md (8 files), .claude/skills/*/SKILL.md,',
  '.claude/workflows/*.js, .claude/hooks/*, tools/checks/*.py, tools/report-render/*,',
  'tools/external/bootstrap.py, engagements/_template/, .gitignore.',
].join('\n');

const LENS_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    lens: { type: 'string' },
    issues: { type: 'array', items: { type: 'object', additionalProperties: false,
      properties: {
        file: { type: 'string' },
        issue: { type: 'string' },
        type: { type: 'string', enum: ['project-specific', 'stale-ref', 'broken-cross-ref', 'doc-code-drift', 'non-generalizable', 'missing-from-docs', 'naming-inconsistent', 'dead-code'] },
        severity: { type: 'string', enum: ['high', 'medium', 'low'] },
        fix: { type: 'string' }
      }, required: ['file', 'issue', 'type', 'severity', 'fix'] } },
    clean: { type: 'boolean' }
  }, required: ['lens', 'issues', 'clean']
};
const SYNTH_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    overall_consistency: { type: 'string', enum: ['fully-agnostic', 'mostly-agnostic-with-fixes', 'has-contamination'] },
    verdict_rationale: { type: 'string' },
    high_priority: { type: 'array', items: { type: 'string' } },
    medium_priority: { type: 'array', items: { type: 'string' } },
    low_priority: { type: 'array', items: { type: 'string' } },
    top_5_fixes: { type: 'array', items: { type: 'string' } }
  }, required: ['overall_consistency', 'verdict_rationale', 'top_5_fixes']
};

phase('Audit');

const lenses = [
  { label: 'project-contamination', prompt: SCOPE + '\n\nROLE: project-contamination scanner. Use Grep/Read. Search for ANY engagement-specific references in the toolkit code and docs (NOT in engagements/ or .lab/) -- real target domains, real IP prefixes, plugin/theme names pinned to specific X.Y.Z versions, admin-style usernames, or operator handles. Any identifier that reads like a real prior target rather than a generic example, appearing in a tool/rule/agent/skill (not an engagement), is contamination. Report each with file, issue, fix. Keep the private deny-list out-of-tree under $PENTEST_AUTH_HOME (gitignored), never in the repo.' },

  { label: 'cross-ref-integrity', prompt: SCOPE + '\n\nROLE: cross-reference integrity auditor. Use Grep/Read. Verify every cross-reference BETWEEN docs is valid: CLAUDE.md references to tools/rules/agents exist at named paths. methodology.md and pitfalls.md cross-refs to each other and to specific tools are correct. Agent files reference tools by name that exist. /pentest SKILL references phases, agents, workflows that exist. Workflow scripts reference tool names that exist. cve_lookup references plugin_cve_research workflow that exists. Report any broken refs.' },

  { label: 'doc-code-drift', prompt: SCOPE + '\n\nROLE: doc-code drift auditor. Use Grep/Read. Check mismatches between docs and code: CLAUDE.md states a tool count in Current state -- count actual tools/checks/*.py and confirm the documented number matches the real count exactly. CLAUDE.md says 8 agents, count .claude/agents/*.md. The tool table in tools/checks/README.md lists ALL tools. The dispatch table in methodology.md names tools that exist. render_report.py supports logo/theme/embed as documented. Report any drift.' },

  { label: 'naming-consistency', prompt: SCOPE + '\n\nROLE: naming-consistency auditor. Use Grep/Read. Check: tool CLI signatures consistent (positional vs flagged args). JSON output shape consistent ({target, ok, findings, note}) across tools. Agent frontmatter consistent (name, description, model, tools). Workflow meta consistent (name, description, phases). Skill frontmatter consistent. Report inconsistencies.' },

  { label: 'completeness-gaps', prompt: SCOPE + '\n\nROLE: completeness-gap auditor. Use Grep/Read. Check: ALL tools/checks/*.py (count them) are documented in BOTH tools/checks/README.md AND CLAUDE.md. ALL new tools mentioned in methodology.md dispatch. The exploiter agent tool list includes new tools. The rules reference plugin_cve_research workflow. All 4 workflows (pentest-assess, qa-gate, plugin_cve_research, toolkit-consistency-audit) listed in CLAUDE.md. Report missing references.' },

  { label: 'dead-code-stale', prompt: SCOPE + '\n\nROLE: dead-code and stale-reference scanner. Use Grep/Read. Check: any imports referencing non-existent modules. Any TODO/FIXME/HACK markers. Any references to specific engagements presented as current state (vs clearly-marked examples). Any temp files left behind. Any broken Python syntax. Report each finding.' },
];

const results = (await parallel(lenses.map(L => () =>
  agent(L.prompt, { schema: LENS_SCHEMA, label: L.label, phase: 'Audit', effort: 'xhigh' }).catch(() => null)
))).map((r, i) => r ? { label: lenses[i].label, out: r } : { label: lenses[i].label, out: { lens: lenses[i].label, issues: [], clean: true, _error: true } });

phase('Synthesize');

const synth = await agent(
  'You are the synthesis lead for a toolkit CONSISTENCY audit. The toolkit must be PROJECT-AGNOSTIC. Aggregate findings. Separate real issues (must fix) from cosmetic. Give overall consistency verdict + top 5 fixes.\n\nSCOPE:\n' + SCOPE + '\n\nAUDIT OUTPUTS:\n' + JSON.stringify(results, null, 2).slice(0, 12000),
  { schema: SYNTH_SCHEMA, label: 'synthesize', phase: 'Synthesize', effort: 'xhigh' }
);

return synth;
