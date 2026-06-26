export const meta = {
  name: 'plugin_cve_research',
  description: 'Systematic CVE research for a WordPress plugin inventory — web-search NVD/Wordfence/Patchstack/WPScan for each plugin+version, filter to applicable+anonymous, return structured CVE leads. Use when wp_fingerprint or MCP leak surfaces the plugin inventory and cve_lookup (OSV) reports a coverage_gap for WP.',
  phases: [
    { title: 'Research', detail: 'parallel web-research agents, auto-grouped ~5 plugins each' },
    { title: 'Synthesize', detail: 'filter to version-applicable + anonymous-exploitable CVE leads' },
  ],
}

// args.plugins = [{slug, name, version}, ...] — the plugin inventory (from wp_fingerprint or MCP leak)
const PLUGINS = (args && args.plugins) || [];

if (!PLUGINS.length) {
  return { error: "no plugins provided. Pass args.plugins = [{slug, name, version}, ...]" };
}

const LENS_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    group: { type: 'string' },
    cves: { type: 'array', items: { type: 'object', additionalProperties: false,
      properties: {
        cve_or_advisory: { type: 'string' },
        plugin: { type: 'string' },
        version_tested: { type: 'string' },
        affected_versions: { type: 'string' },
        applies: { type: 'string', enum: ['yes', 'no', 'uncertain'] },
        anonymous: { type: 'string', enum: ['yes', 'no', 'needs-auth', 'uncertain'] },
        severity: { type: 'string' },
        impact: { type: 'string' },
        exploitation_path: { type: 'string' },
        source_url: { type: 'string' },
        sources: { type: 'array', items: { type: 'string' }, description: '>=2 authoritative source URLs (NVD / GitHub Advisory GHSA / WPScan / Patchstack / Wordfence). REQUIRED to state a CVE as fact.' },
        corroboration: { type: 'string', enum: ['corroborated', 'unverified'], description: "corroborated ONLY if confirmed against >=2 authoritative sources; else unverified (possible hallucination — do NOT present as fact)" }
      }, required: ['cve_or_advisory', 'plugin', 'applies', 'anonymous', 'corroboration'] } },
    no_cves_found_for: { type: 'array', items: { type: 'string' } }
  }, required: ['group', 'cves']
};
const SYNTH_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    applicable_cves: { type: 'array', items: { type: 'object', additionalProperties: true,
      properties: { cve: {type:'string'}, plugin: {type:'string'}, version: {type:'string'}, anonymous: {type:'string'}, severity: {type:'string'}, impact: {type:'string'}, exploitation_path: {type:'string'}, source: {type:'string'} }, required: ['cve','plugin'] } },
    needs_auth_cves: { type: 'array', items: { type: 'string' } },
    clean_plugins: { type: 'array', items: { type: 'string' } },
    summary: { type: 'string' }
  }, required: ['applicable_cves', 'summary']
};

phase('Research');

// auto-group plugins into batches of ~5
const GROUP_SIZE = 5;
const groups = [];
for (let i = 0; i < PLUGINS.length; i += GROUP_SIZE) {
  groups.push(PLUGINS.slice(i, i + GROUP_SIZE));
}

const results = (await parallel(groups.map((grp, gi) => () =>
  agent(
    `You are a WordPress security researcher. Use WebSearch to find EVERY CVE/advisory for these WordPress plugins at their EXACT versions. For each CVE: is the installed version in the affected range (applies: yes/no/uncertain)? Is it exploitable without login (anonymous: yes/no/needs-auth/uncertain)? What is the exploitation path? Check NVD, Wordfence, Patchstack, WPScan, and the vendor advisory.\n\nPLUGINS TO RESEARCH:\n${JSON.stringify(grp, null, 2)}\n\nReturn ALL CVEs found (including ones that DON'T apply — mark applies:no). Be thorough — missing a CVE is worse than a false alarm.\n\nCRITICAL — DO NOT FABRICATE CVE IDs: for EVERY CVE you report, you MUST WebSearch and cite >=2 authoritative source URLs (NVD, GitHub Advisory GHSA, WPScan, Patchstack, or Wordfence) in the "sources" field and set corroboration:"corroborated". If you cannot confirm a CVE against >=2 authoritative sources, set corroboration:"unverified" (it may be a hallucination) — never state an uncorroborated CVE as fact. A fabricated CVE that reaches a client report is far worse than a missed one.`,
    { schema: LENS_SCHEMA, label: `group-${gi+1}`, phase: 'Research', effort: 'xhigh' }
  ).catch(() => null)
))).map((r, i) => r ? { label: `group-${i+1}`, out: r } : { label: `group-${i+1}`, out: { group: `group-${i+1}`, cves: [], no_cves_found_for: [] } });

phase('Synthesize');

const synth = await agent(
  `You are the synthesis lead for a plugin-CVE research pass. Aggregate the research outputs. Filter to ONLY CVEs that (a) apply to the EXACT installed versions (applies=yes), AND separate them by anonymous exploitability. Return the applicable CVEs (with exploitation paths) for the report's leads[], the needs-auth CVEs (for when accounts are provisioned), and the clean plugins (no applicable CVEs). Be honest — a version-match is a LEAD per pitfalls.md 'version banner ≠ vuln'; note when a defense layer (WAF/HMAC/config) blocks exploitation on the target.\n\nCORROBORATION GATE (critical): EXCLUDE any CVE with corroboration:"unverified" from applicable_cves — it could not be confirmed against >=2 authoritative sources and is likely a hallucination. If you retain any unverified CVE for completeness, flag it explicitly as UNVERIFIED in the summary and never present it as a confirmed lead. Only corroborated CVEs reach applicable_cves.\n\nPLUGIN INVENTORY:\n${JSON.stringify(PLUGINS, null, 2)}\n\nRESEARCH OUTPUTS:\n${JSON.stringify(results, null, 2)}`,
  { schema: SYNTH_SCHEMA, label: 'synthesize', phase: 'Synthesize', effort: 'xhigh' }
);

return synth;
