#!/usr/bin/env python
"""render_report.py — turn an engagement findings.json into the deliverable set:
report.md (human), report.html (dark, on-screen), report-light.html (print/PDF).
findings.json is the SINGLE SOURCE OF TRUTH — md + html are both generated from
it, so they can never drift. HTML uses a dark-glass design system
(report.css / report-light.css), CSS inlined into a self-contained file.

STANDALONE HTML: by default the referenced evidence artifacts are embedded INLINE in
report.html (text in collapsible blocks, screenshots as base64) so a client who
receives only report.html has the full evidence — no loose files. Embedded text is
redaction-neutralized on the way in (the same chokepoint that refuses to render
credential material). Use --no-embed-evidence for a lean report that ships evidence
separately. (Markdown keeps a reference index — it is the working format, not the
single-file client artifact.)

Usage:
  python render_report.py <findings.json>                      # report.html (dark, evidence embedded)
  python render_report.py <findings.json> out.html --theme light
  python render_report.py <findings.json> --md                 # report.md
  python render_report.py <findings.json> --all                # report.md + report.html (dark)
  python render_report.py <findings.json> --no-embed-evidence  # reference index instead of inline evidence
  python render_report.py <findings.json> out.html --theme light   # light/print theme (opt-in)

findings.json schema (all text fields optional, rendered when present):
{
  "engagement": {"name","target","type","authorization","date","operator","classification","brand","theme"},
  "overall_risk": "Medium-High", "risk_tier": "high", "headline": "...", "summary": "...",
  "business_risk": "...",                 # OPTIONAL -> Executive-view business-impact paragraph (falls back to summary/headline)
  "counts": {"critical":0,"high":1,"medium":4,"low":2,"info":10},
  "findings": [{"id","title","severity","cvss_vector","cvss_score","cwe","location",
                "description","reproduction":[..],"evidence":[..],
                "remediation","remediation_code","verification","validation_status",
                "owasp","wstg","attack",                       # owasp/wstg/attack -> per-finding standards line
                "business_impact","effort"}],                  # OPTIONAL -> Executive-view one-liner + roadmap effort tag (S/M/L)
  "informational": [{"id","title","cwe","description","remediation","evidence"}],
  "leads": [{"id","title","basis","followup"}],
  "evidence_index": [{"file","contents","ref"}],
  "method": "...", "standards": "...",
  # --- standards coverage section (rendered as report section 4) ---
  "asvs_level": "ASVS 4.0 L1 ...",                       # target verification level
  "coverage": [{"area","status","notes"}],              # -> WSTG/ASVS/API coverage matrix
  "limitations": ["honest coverage gap", ...],          # -> coverage-limitations list (skipped test = stated gap)
  "compliance": "PCI/SOC2/ISO mapping ..."              # -> compliance mapping line
}
"""
import sys, os, json, html, re, base64

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

def e(x):
    return html.escape(str(x if x is not None else ""))

def sev_class(sev):
    s = (sev or "info").strip().lower()
    return s if s in SEV_ORDER else "info"

def sorted_findings(d):
    return sorted(d.get("findings", []), key=lambda f: SEV_ORDER.get(sev_class(f.get("severity")), 9))

def band_of(score):
    try: s = float(score)
    except (TypeError, ValueError): return None
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s >= 0.1 else "info"

def is_downrated(f):
    """True if severity is intentionally BELOW its CVSS band — i.e. the cvss_score is an
    ADVISORY/component score, not the demonstrated severity (e.g. Low finding, advisory 7.5)."""
    b = band_of(f.get("cvss_score"))
    return bool(b and SEV_ORDER[sev_class(f.get("severity"))] > SEV_ORDER[b])

def is_uprated(f):
    """True if severity is rated ABOVE its CVSS band (e.g. Critical severity with a
    high-band 7.x score) — the inverse of is_downrated. Legitimate (business context
    can justify raising severity) but must be transparent, never silent."""
    b = band_of(f.get("cvss_score"))
    return bool(b) and SEV_ORDER[sev_class(f.get("severity"))] < SEV_ORDER[b]

def compute_counts(d):
    """Severity counts derived from findings[] (the source of truth), so the scoreboard
    can never drift from the actual findings even if a stale `counts` is declared."""
    c = {s: 0 for s in SEV_ORDER}
    for f in d.get("findings", []):
        c[sev_class(f.get("severity"))] += 1
    c["info"] = len(d.get("informational", []))   # info is authoritative from informational[] (matches finding_schema.py exactly)
    return c

# ===================== evidence embedding (standalone deliverable) =====================
# A client receives ONLY report.html — so the evidence that backs each finding must travel
# INSIDE it, not as loose files under evidence/. This resolves every referenced artifact,
# redaction-neutralizes text on the way in, base64-inlines images, and truncates (never
# silently drops) anything oversized. Result: report.html is fully self-contained.

_IMG_MIME = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
             ".gif": "image/gif", ".webp": "image/webp", ".svg": "image/svg+xml", ".bmp": "image/bmp"}
_EMBED_TEXT_EXT = {".md", ".txt", ".json", ".xml", ".log", ".csv", ".yaml", ".yml",
                   ".html", ".htm", ".js", ".css", ".sh", ".py", ".http", ".har", ".ini", ".conf"}
_TEXT_CAP = 80_000          # chars inlined per text artifact (then truncated + noted)
_IMG_CAP = 2_000_000        # raw bytes inlined per image (over this -> noted, not embedded)
_FILE_TOK = re.compile(r'[A-Za-z0-9][A-Za-z0-9._\-/]*\.[A-Za-z0-9]{1,6}')

def _expand_braces(s):
    """'dir/{a.json,b.txt}' -> 'dir/a.json dir/b.txt' so brace-listed refs tokenize."""
    return re.sub(r'([A-Za-z0-9._\-/]*)\{([^}]*)\}',
                  lambda m: " ".join(m.group(1) + i.strip() for i in m.group(2).split(",")),
                  str(s))

class Evidence:
    """Resolves evidence-file references in findings.json to real artifacts under the
    engagement dir and embeds them inline. Text is redaction-neutralized on the way in;
    images become base64 data URIs. Anchors let per-finding evidence bullets link to the
    embedded block in the appendix."""
    def __init__(self, base, redactor=None):
        self.base = os.path.abspath(base) if base else None
        self.roots = [os.path.join(self.base, "evidence"), self.base] if self.base else []
        self.redactor = redactor
        self.anchor = {}      # fullpath -> "ev-N" (insertion order == anchor order)
        self.label = {}       # fullpath -> display path (relative to evidence/)
        self.captions = {}    # fullpath -> (contents, ref) from evidence_index
        self.warnings = []
        self._n = 0

    def files(self, s):
        return _FILE_TOK.findall(_expand_braces(s)) if s else []

    def find(self, token):
        """Resolve a referenced token to a real file under evidence/ (or the engagement
        root), refusing any path that escapes the engagement dir."""
        if not self.base:
            return None
        rel = str(token).strip().lstrip("/").replace("\\", "/")
        if not rel:
            return None
        for root in self.roots:
            rootabs = os.path.abspath(root)
            full = os.path.abspath(os.path.join(rootabs, rel))
            try:
                if os.path.commonpath([rootabs, full]) != rootabs:
                    continue
            except ValueError:
                continue
            if os.path.isfile(full):
                return full
        return None

    def register(self, token):
        full = self.find(token)
        if not full:
            return None
        if full not in self.anchor:
            self._n += 1
            self.anchor[full] = f"ev-{self._n}"
            self.label[full] = self._display(full)
        return self.anchor[full]

    def _display(self, full):
        for root in self.roots:
            rootabs = os.path.abspath(root)
            try:
                if os.path.commonpath([rootabs, full]) == rootabs:
                    return os.path.relpath(full, rootabs).replace("\\", "/")
            except ValueError:
                pass
        return os.path.basename(full)

    def _ev_strings(self, item):
        v = item.get("evidence")
        if isinstance(v, list):
            return v
        return [v] if v else []

    def register_all(self, d):
        """Pre-pass: register every referenced artifact so anchors exist before findings
        render (bullets link to them) and the appendix can embed each exactly once."""
        for f in d.get("findings", []):
            for s in self._ev_strings(f):
                for t in self.files(s):
                    self.register(t)
        for i in d.get("informational", []):
            for s in self._ev_strings(i):
                for t in self.files(s):
                    self.register(t)
        for x in d.get("evidence_index", []):
            for t in self.files(x.get("file", "")):
                if self.register(t):
                    full = self.find(t)
                    if full and full not in self.captions:
                        self.captions[full] = (x.get("contents", ""), x.get("ref", ""))

    def linkify(self, s):
        """Render an evidence string, turning each resolvable file token into a link to
        its embedded appendix block; everything else is HTML-escaped text."""
        s = str(s)
        out, last = [], 0
        for m in _FILE_TOK.finditer(s):
            out.append(e(s[last:m.start()]))
            aid = self.anchor.get(self.find(m.group(0)) or "")
            out.append(f'<a class="ev-link" href="#{aid}">{e(m.group(0))}</a>' if aid else e(m.group(0)))
            last = m.end()
        out.append(e(s[last:]))
        return "".join(out)

    def block(self, full):
        aid, name = self.anchor[full], self.label[full]
        ext = os.path.splitext(full)[1].lower()
        cap = self.captions.get(full)
        cap_html = ""
        if cap and (cap[0] or cap[1]):
            cap_html = (f'<p class="ev-cap">{e(cap[0])}'
                        + (f' <span class="ev-ref">({e(cap[1])})</span>' if cap[1] else "") + "</p>")
        if ext in _IMG_MIME:
            try:
                raw = open(full, "rb").read()
            except OSError as ex:
                self.warnings.append(f"{name}: unreadable ({ex})"); return ""
            if len(raw) > _IMG_CAP:
                body = (f'<p class="ev-note">[image artifact {len(raw)//1024} KB — too large to '
                        f'inline; provided as a separate file]</p>')
            else:
                body = (f'<img class="ev-img" alt="{e(name)}" '
                        f'src="data:{_IMG_MIME[ext]};base64,{base64.b64encode(raw).decode()}">')
        elif ext in _EMBED_TEXT_EXT or ext == "":
            try:
                txt = open(full, encoding="utf-8", errors="replace").read()
            except OSError as ex:
                self.warnings.append(f"{name}: unreadable ({ex})"); return ""
            if self.redactor:
                txt, hits = self.redactor(txt)
                if hits:
                    self.warnings.append(f"{name}: {hits} credential-pattern hit(s) redacted on embed")
            if len(txt) > _TEXT_CAP:
                txt = txt[:_TEXT_CAP] + f"\n\n[... truncated for the report — full artifact is {len(txt)//1024} KB ...]"
            body = f'<pre class="ev-pre"><code>{e(txt)}</code></pre>'
        else:
            body = '<p class="ev-note">[binary artifact — provided as a separate file]</p>'
        return (f'<details class="ev-item" id="{aid}"><summary><code>{e(name)}</code></summary>'
                f'{cap_html}{body}</details>')

    def render_appendix(self, d):
        """The appendix as embedded artifacts (assumes register_all already ran)."""
        if not self.anchor:
            return ""
        blocks = "".join(self.block(fp) for fp in self.anchor)   # dict preserves anchor order
        return (f'<section class="evidence-block"><h2>Appendix — evidence artifacts</h2>'
                f'<p class="ev-intro">Every finding traces to a reproduction. The artifacts below are '
                f'embedded in full (secrets and PII redacted) so this report is self-contained — no '
                f'external files are needed to review the evidence. Click an artifact to expand it.</p>'
                f'{blocks}</section>')

# ===================== HTML =====================

def _block(title, inner):
    return f'<div class="block"><h4>{e(title)}</h4>{inner}</div>' if inner else ""

def render_finding_html(f, embed=None):
    sev = sev_class(f.get("severity"))
    badge = SEV_LABEL[sev]
    dr = is_downrated(f); up = is_uprated(f)
    if f.get("cvss_score") is not None:
        if dr:   badge += f" · adv. {e(f['cvss_score'])}"
        elif up: badge += f" · {e(f['cvss_score'])} (raised)"
        else:    badge += f" · {e(f['cvss_score'])}"
    meta = []
    if f.get("cwe"):         meta.append(f'<span><b>Class:</b> {e(f["cwe"])}</span>')
    if f.get("cvss_vector"):
        _lbl = "Advisory CVSS" if dr else ("CVSS (severity raised above band)" if up else "CVSS")
        meta.append(f'<span><b>{_lbl}:</b> <code>{e(f["cvss_vector"])}</code></span>')
    if f.get("location"):    meta.append(f'<span><b>Location:</b> <code>{e(f["location"])}</code></span>')
    if f.get("validation_status"): meta.append(f'<span><b>Confidence:</b> {e(f["validation_status"])}</span>')
    if f.get("finding_uid"): meta.append(f'<span><b>Tracking ID:</b> {e(f["finding_uid"])}</span>')
    if f.get("derived_from"):  # chain finding: cite the primitives it composes
        _df = f["derived_from"]
        _df = ", ".join(str(x) for x in _df) if isinstance(_df, list) else str(_df)
        meta.append(f'<span><b>Chain — derived from:</b> {e(_df)}</span>')
    if f.get("owasp"):       meta.append(f'<span><b>OWASP:</b> {e(f["owasp"])}</span>')
    if f.get("wstg"):        meta.append(f'<span><b>WSTG:</b> {e(f["wstg"])}</span>')
    if f.get("attack") and f["attack"] != "—": meta.append(f'<span><b>ATT&amp;CK:</b> {e(f["attack"])}</span>')
    meta_html = f'<div class="card__meta">{"".join(meta)}</div>' if meta else ""
    narrative = f'<p class="card__narrative">{e(f.get("description",""))}</p>' if f.get("description") else ""
    repro = ""
    rp = f.get("reproduction")
    if rp:
        if isinstance(rp, list):
            repro = _block("Reproduction", "<ol>" + "".join(f"<li>{e(s)}</li>" for s in rp) + "</ol>")
        else:
            repro = _block("Reproduction", f"<p>{e(rp)}</p>")
    ev = ""
    if embed:  # evidence refs only when the appendix actually embeds them (else they'd dangle)
        evl = f.get("evidence")
        if evl:
            if isinstance(evl, list):
                ev = _block("Evidence", "<ul>" + "".join(f"<li>{embed.linkify(s)}</li>" for s in evl) + "</ul>")
            else:
                ev = _block("Evidence", f"<p>{embed.linkify(evl)}</p>")
    rem = ""
    if f.get("remediation"):
        inner = f'<p>{e(f["remediation"])}</p>'
        if f.get("remediation_code"):
            inner += f'<pre class="code"><code>{e(f["remediation_code"])}</code></pre>'
        rem = _block("Remediation", inner)
    ver = _block("Verification", f'<p>{e(f["verification"])}</p>') if f.get("verification") else ""
    return f'''<article class="card card--{sev}" id="{e(f.get("id",""))}">
  <div class="card__head">
    <div><p class="card__kicker">{e(f.get("id",""))}</p><h2 class="card__title">{e(f.get("title",""))}</h2></div>
    <span class="card__badge sev--{sev}">{e(badge)}</span>
  </div>
  {meta_html}{narrative}{repro}{ev}{rem}{ver}
</article>'''

def render_info_html(i, embed=None):
    meta = f'<div class="card__meta"><span><b>Class:</b> {e(i["cwe"])}</span></div>' if i.get("cwe") else ""
    narrative = f'<p class="card__narrative">{e(i.get("description",""))}</p>' if i.get("description") else ""
    rem = _block("Remediation", f'<p>{e(i["remediation"])}</p>') if i.get("remediation") else ""
    ev = ""
    if embed and i.get("evidence"):
        ev = _block("Evidence", f'<p>{embed.linkify(i["evidence"])}</p>')
    return f'''<article class="card card--info" id="{e(i.get("id",""))}">
  <div class="card__head">
    <div><p class="card__kicker">{e(i.get("id",""))}</p><h2 class="card__title">{e(i.get("title",""))}</h2></div>
    <span class="card__badge sev--info">Info</span>
  </div>
  {meta}{narrative}{rem}{ev}
</article>'''

def _clip(s, n):
    s = str(s or "")
    return s if len(s) <= n else s[:n].rstrip() + "…"

def _roadmap_tier(label, items, hint):
    """One priority tier of the fix-first roadmap (rendered only if non-empty)."""
    if not items:
        return ""
    lis = "".join(
        f'<li><code>{e(f.get("id",""))}</code> {e(f.get("title",""))}'
        + (f' <span class="exec__effort">{e(f["effort"])}</span>' if f.get("effort") else "") + '</li>'
        for f in items)
    return (f'<div class="exec__tier"><h5>{e(label)} <span class="exec__tier-n">({len(items)})</span></h5>'
            f'<p class="exec__hint">{e(hint)}</p><ul>{lis}</ul></div>')

def render_exec_view(d, risk_tier):
    """One-page Executive View for leadership: a business-risk verdict, the top risks
    stated as business impact, a prioritized fix-first remediation roadmap, and a
    coverage/assurance line. Sits ABOVE the technical findings so a CISO/board reader
    gets the decision-relevant picture without the per-finding detail. Fields
    business_risk / business_impact / effort are OPTIONAL — when absent the view falls
    back to summary / description, so existing findings.json still renders."""
    findings = sorted_findings(d)
    verdict = d.get("overall_risk", "Risk")
    br = d.get("business_risk") or d.get("summary") or d.get("headline", "")
    top = findings[:3]
    if top:
        top_html = "".join(
            f'<li><span class="exec__pill sev--{sev_class(f.get("severity"))}">{SEV_LABEL[sev_class(f.get("severity"))]}</span>'
            f'<span class="exec__risk-title">{e(f.get("title",""))}</span>'
            f'<span class="exec__risk-where">{e(f.get("location",""))}</span>'
            f'<span class="exec__risk-impact">{e(f.get("business_impact") or _clip(f.get("description",""), 150))}</span></li>'
            for f in top)
    else:
        top_html = '<li class="exec__none">No confirmed findings.</li>'
    fix_now = [f for f in findings if sev_class(f.get("severity")) in ("critical", "high")]
    fix_soon = [f for f in findings if sev_class(f.get("severity")) == "medium"]
    schedule = [f for f in findings if sev_class(f.get("severity")) in ("low", "info")]
    roadmap = (_roadmap_tier("Fix now", fix_now, "Critical / High — remediate before the next release.")
               + _roadmap_tier("Fix soon", fix_soon, "Medium — schedule in the current sprint cycle.")
               + _roadmap_tier("Schedule / hardening", schedule, "Low + hardening — batch into routine hardening."))
    if not roadmap:
        roadmap = '<p class="exec__none">No confirmed findings to remediate.</p>'
    cov = d.get("coverage") or []
    tested = sum(1 for c in cov if str(c.get("status", "")).lower() in ("tested", "pass", "covered"))
    gaps = len(cov) - tested
    cov_line = f"{tested} of {len(cov)} in-scope areas tested" if cov else "coverage not summarized"
    if gaps:
        cov_line += f" · {gaps} stated gap(s)"
    comp = d.get("compliance")
    cov_html = (f'<p class="exec__coverage"><b>Coverage:</b> {e(cov_line)}'
                + (f' · <b>Compliance:</b> {e(comp)}' if comp else "") + '</p>')
    return f'''<section class="exec-view">
  <header class="exec__head">
    <h2 class="exec__title">Executive summary</h2>
    <span class="exec__verdict sev--{risk_tier}">{e(verdict)}</span>
  </header>
  <p class="exec__risk">{e(br)}</p>
  <div class="exec__grid">
    <div class="exec__col">
      <h4 class="exec__h">Top risks (business impact)</h4>
      <ul class="exec__top">{top_html}</ul>
    </div>
    <div class="exec__col">
      <h4 class="exec__h">Remediation roadmap (fix-first)</h4>
      <div class="exec__roadmap">{roadmap}</div>
    </div>
  </div>
  {cov_html}
</section>'''

def render_html(d, css, embed=None):
    if embed:
        embed.register_all(d)   # assign anchors before findings render (bullets link to them)
    eng = d.get("engagement", {}) or {}
    target = eng.get("target") or eng.get("name") or "Target"
    brand = eng.get("brand", "Redan")
    _logo = eng.get("_logo_datauri")
    brand_mark_html = (f'<img class="report__brand-logo" src="{_logo}" alt="{e(brand)}">'
                       if _logo else f'<span class="report__brand-mark">{e(brand[0] if brand else "P")}</span>')
    _dt = d.get("risk_tier")
    if _dt and sev_class(_dt) in SEV_ORDER:
        risk_tier = sev_class(_dt)
    else:
        _fs = sorted_findings(d)
        risk_tier = sev_class(_fs[0]["severity"]) if _fs else "info"  # derive from worst finding — no silent 'info' understatement
    counts = compute_counts(d)
    score_cards = "".join(
        f'<div class="score score--{s}"><span class="score__n">{e(counts.get(s,0))}</span><span class="score__label">{SEV_LABEL[s]}</span></div>'
        for s in ["critical", "high", "medium", "low", "info"])
    hmeta = [f'<span><b>{lbl}:</b> {e(eng[k])}</span>' for lbl, k in
             [("Engagement","name"),("Date","date"),("Authorization","authorization"),("Type","type")] if eng.get(k)]
    hero_meta = f'<div class="hero__meta">{"".join(hmeta)}</div>' if hmeta else ""
    findings_html = "".join(render_finding_html(f, embed) for f in sorted_findings(d))
    info_html = "".join(render_info_html(i, embed) for i in d.get("informational", []))
    leads = d.get("leads", [])
    leads_html = ""
    if leads:
        items = "".join(
            f'<div class="lead"><h3>{e(l.get("id",""))} — {e(l.get("title",""))}</h3>'
            + (f'<p><b>Basis:</b> {e(l["basis"])}</p>' if l.get("basis") else "")
            + (f'<p><b>Follow-up:</b> {e(l["followup"])}</p>' if l.get("followup") else "") + "</div>"
            for l in leads)
        leads_html = f'<section class="leads"><h2>Leads — unconfirmed, for follow-up</h2>{items}</section>'
    # The evidence appendix is only relevant when artifacts are EMBEDDED inline (the
    # report is then self-contained). When evidence is NOT embedded, a standalone
    # report has no appendix — each finding stands on its in-report Reproduction steps.
    ev_html = embed.render_appendix(d) if embed else ""
    exec_view_html = render_exec_view(d, risk_tier)
    method_html = ""
    if d.get("method") or d.get("standards"):
        mp = f'<p class="card__narrative">{e(d.get("method",""))}</p>' if d.get("method") else ""
        sp = _block("Standards", f'<p>{e(d["standards"])}</p>') if d.get("standards") else ""
        method_html = (f'<article class="card card--info"><div class="card__head"><div>'
            f'<p class="card__kicker">How we tested</p><h2 class="card__title">Methodology</h2></div></div>{mp}{sp}</article>')
    coverage_html = ""
    cov = d.get("coverage"); lim = d.get("limitations")
    if cov or lim or d.get("asvs_level") or d.get("compliance"):
        rows = "".join(
            f'<tr><td>{e(c.get("area",""))}</td><td>{e(c.get("status",""))}</td><td>{e(c.get("notes",""))}</td></tr>'
            for c in (cov or []))
        cov_table = (f'<table class="cov"><thead><tr><th>Area</th><th>Status</th><th>Notes</th></tr></thead>'
                     f'<tbody>{rows}</tbody></table>') if cov else ""
        lim_html = ("<h4>Coverage limitations (a skipped test is a stated gap, not a clean result)</h4><ul>"
                    + "".join(f"<li>{e(x)}</li>" for x in (lim or [])) + "</ul>") if lim else ""
        asvs = f'<p><b>ASVS target:</b> {e(d["asvs_level"])}</p>' if d.get("asvs_level") else ""
        comp = f'<p><b>Compliance mapping:</b> {e(d["compliance"])}</p>' if d.get("compliance") else ""
        coverage_html = (f'<article class="card card--info"><div class="card__head"><div>'
            f'<p class="card__kicker">Standards &amp; coverage</p>'
            f'<h2 class="card__title">Standards coverage &amp; limitations</h2></div></div>'
            f'{asvs}{cov_table}{lim_html}{comp}</article>')
    retest_html = ""
    rt = d.get("retest")
    if rt:
        s = rt.get("summary", {})
        def _rt_rows(items):
            return "".join(f'<li><code>{e(x.get("uid",""))}</code> — {e(x.get("title",""))} '
                           f'<span class="exec__pill sev--{sev_class(x.get("severity"))}">{e(x.get("severity",""))}</span>'
                           f'{(" — <em>" + e(x.get("verified")) + "</em>") if x.get("verified") else ""}</li>'
                           for x in (items or []))
        _blocks = ""
        for _lbl, _k, _note in [("Regressed", "regressed", "previously fixed, now back — priority"),
                                ("Still open", "still_open", "persisted since the last test"),
                                ("Fixed", "fixed", "remediated since the last test"),
                                ("New", "new", "first seen this test")]:
            _items = rt.get(_k)
            if _items:
                _blocks += (f'<div class="block"><h4>{_lbl} ({len(_items)}) '
                            f'<span class="exec__hint">{_note}</span></h4><ul>{_rt_rows(_items)}</ul></div>')
        _date = f' (re-tested {e(rt["date"])})' if rt.get("date") else ""
        _note_html = f'<p class="card__note">{e(rt["note"])}</p>' if rt.get("note") else ""
        retest_html = (f'<article class="card card--info"><div class="card__head"><div>'
            f'<p class="card__kicker">Retest</p><h2 class="card__title">Retest / remediation delta{_date}</h2></div></div>'
            f'<div class="card__meta"><span><b>Fixed:</b> {s.get("fixed",0)}</span>'
            f'<span><b>Still open:</b> {s.get("still_open",0)}</span>'
            f'<span><b>New:</b> {s.get("new",0)}</span>'
            f'<span><b>Regressed:</b> {s.get("regressed",0)}</span></div>{_note_html}{_blocks}</article>')
    classification = eng.get("classification")  # declared handling label — NOT defaulted; a report carries a confidentiality marking only when the engagement explicitly sets one
    classification_html = f'<span class="confidential">{e(classification)}</span>' if classification else ""
    evidence_note = ("Evidence artifacts are embedded inline above (secrets/PII redacted) so this file is self-contained."
                     if (embed and getattr(embed, "anchor", None)) else
                     "Every confirmed finding above includes its reproduction steps.")
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{e(target)} — Penetration Test Report</title>
<style>
{css}
</style>
</head>
<body>
<main class="report">
  <header class="hero hero--{risk_tier}">
    <div class="report__brand">{brand_mark_html} {e(brand)}</div>
    <p class="hero__eyebrow">Penetration Test Report</p>
    <h1 class="hero__name">{e(target)}</h1>
    <p class="hero__url">{e(eng.get("operator",""))}</p>
    <div class="hero__verdict">
      <span class="hero__tier sev--{risk_tier}">{e(d.get("overall_risk","Risk"))}</span>
      <p class="hero__headline">{e(d.get("headline", d.get("summary","")[:240]))}</p>
    </div>
    {hero_meta}
  </header>
  <section class="scoreboard" aria-label="Findings by severity">{score_cards}</section>
  {exec_view_html}
  {retest_html}
  {method_html}
  {coverage_html}
  <h2 class="section-h">Findings</h2>
  {findings_html or '<p style="color:var(--muted)">No confirmed findings.</p>'}
  {('<h2 class="section-h">Informational / hardening</h2>' + info_html) if info_html else ''}
  {leads_html}
  {ev_html}
  <footer class="report__footer">
    <p class="report__method">Engagement: {e(eng.get("name",""))} · Authorization: {e(eng.get("authorization",""))}</p>
    <p class="report__disclaimer">Testing was conducted under the engagement's recorded authorization and rules of engagement. Credentials and secrets were redacted (automated scan clean). Low-sensitivity identifiers that are themselves the subject of a finding (e.g. a public enumeration value) are retained as evidence. {evidence_note}</p>
    {classification_html}
  </footer>
</main>
</body>
</html>'''

# ===================== Markdown =====================

def render_finding_md(f):
    sev = SEV_LABEL[sev_class(f.get("severity"))]
    out = [f"### {f.get('id','')} — {f.get('title','')}", ""]
    if f.get("cwe"):         out.append(f"**Class:** {f['cwe']}  ")
    dr = is_downrated(f); up = is_uprated(f)
    score = f.get("cvss_score")
    if dr and score is not None:
        vec = f" `{f['cvss_vector']}`" if f.get("cvss_vector") else ""
        out.append(f"**Severity:** {sev} · **advisory CVSS {score}**{vec} (rated below the CVSS band — demonstrated impact is {sev}; see Verification)  ")
    elif up and score is not None:
        vec = f" `{f['cvss_vector']}`" if f.get("cvss_vector") else ""
        out.append(f"**Severity:** {sev} · **CVSS {score}**{vec} (severity raised above the CVSS band — see Verification)  ")
    elif f.get("cvss_vector"):
        out.append(f"**CVSS 3.1:** `{f['cvss_vector']}` — {score} ({sev})  ")
    elif score is not None:
        out.append(f"**CVSS:** {score} ({sev})  ")
    else:
        out.append(f"**Severity:** {sev}  ")
    if f.get("location"):    out.append(f"**Location:** {f['location']}  ")
    if f.get("finding_uid"): out.append(f"**Tracking ID:** `{f['finding_uid']}` (stable across re-tests)  ")
    if f.get("validation_status"): out.append(f"**Confidence:** {f['validation_status']}  ")
    if f.get("derived_from"):
        _df = f["derived_from"]
        _df = ", ".join(str(x) for x in _df) if isinstance(_df, list) else str(_df)
        out.append(f"**Chain — derived from:** {_df}  ")
    std = " · ".join(x for x in [
        (f"OWASP {f['owasp']}" if f.get("owasp") else ""),
        (f["wstg"] if f.get("wstg") else ""),
        (f"ATT&CK {f['attack']}" if f.get("attack") and f["attack"] != "—" else "")] if x)
    if std: out.append(f"**Standards:** {std}  ")
    out.append("")
    if f.get("description"): out += [f["description"], ""]
    rp = f.get("reproduction")
    if rp:
        out.append("**Reproduction:**"); out.append("")
        if isinstance(rp, list):
            out += [f"{n}. {s}" for n, s in enumerate(rp, 1)]
        else:
            out.append(rp)
        out.append("")
    evl = f.get("evidence")
    if evl:
        out.append("**Evidence:**"); out.append("")
        out += ([f"- {s}" for s in evl] if isinstance(evl, list) else [evl]); out.append("")
    if f.get("remediation"):
        out += ["**Remediation:**", "", f["remediation"]]
        if f.get("remediation_code"):
            out += ["", "```", f["remediation_code"], "```"]
        out.append("")
    if f.get("verification"): out += [f"**Verification:** {f['verification']}", ""]
    out += ["---", ""]
    return out

def render_retest_md(rt):
    s = rt.get("summary", {})
    date = f" (re-tested {rt['date']})" if rt.get("date") else ""
    L = [f"## 1b. Retest / remediation delta{date}", "",
         "| Outcome | Count |", "|---|---|",
         f"| Fixed (remediated since last test) | {s.get('fixed',0)} |",
         f"| Still open (persisted) | {s.get('still_open',0)} |",
         f"| New (first seen this test) | {s.get('new',0)} |",
         f"| Regressed (was fixed, returned — priority) | {s.get('regressed',0)} |", ""]
    if rt.get("note"):
        L += [f"> {rt['note']}", ""]
    def lst(title, items):
        if not items:
            return []
        return [f"**{title}:**", ""] + [f"- `{x.get('uid','')}` — {x.get('title','')} ({x.get('severity','')})"
                                        + (f" — _{x['verified']}_" if x.get('verified') else "") for x in items] + [""]
    L += lst("Regressed (priority — a previously-fixed issue is back)", rt.get("regressed"))
    L += lst("Still open", rt.get("still_open"))
    L += lst("Fixed", rt.get("fixed"))
    L += lst("New", rt.get("new"))
    L += ["---", ""]
    return L

def render_markdown(d):
    eng = d.get("engagement", {}) or {}
    target = eng.get("target") or eng.get("name") or "Target"
    counts = compute_counts(d)
    L = [f"# Penetration Test Report — {target}", ""]
    for lbl, k in [("Engagement","name"),("Report date","date"),("Authorization","authorization"),
                   ("Type","type"),("Classification","classification")]:
        if eng.get(k): L.append(f"**{lbl}:** {eng[k]}  ")
    L += ["", "---", "", "## 1. Executive summary", ""]
    if d.get("overall_risk"): L += [f"**Overall risk:** {d['overall_risk']}.", ""]
    if d.get("business_risk"): L += [d["business_risk"], ""]
    elif d.get("summary"): L += [d["summary"], ""]
    L += ["**Severity counts (confirmed findings):**", "", "| Severity | Count |", "|---|---|"]
    L += [f"| {SEV_LABEL[s]} | {counts.get(s,0)} |" for s in ["critical","high","medium","low","info"]]
    L.append("")
    _fs = sorted_findings(d)
    _tiers = [("Fix now (Critical/High)", [f for f in _fs if sev_class(f.get("severity")) in ("critical", "high")]),
              ("Fix soon (Medium)", [f for f in _fs if sev_class(f.get("severity")) == "medium"]),
              ("Schedule / hardening (Low + Info)", [f for f in _fs if sev_class(f.get("severity")) in ("low", "info")])]
    if any(items for _, items in _tiers):
        L += ["**Remediation roadmap (fix-first):**", ""]
        for _label, _items in _tiers:
            if _items:
                L.append(f"- **{_label}:** " + "; ".join(f"{f.get('id','')} — {f.get('title','')}" for f in _items))
        L.append("")
    if d.get("retest"):
        L += render_retest_md(d["retest"])
    if eng.get("authorization"):
        L += ["## 2. Scope & authorization", "",
              f"Authorization basis: **{eng.get('type','')}** — {eng['authorization']}. "
              f"Target: `{target}`. Testing was non-destructive; credentials redacted.", ""]
    if d.get("method") or d.get("standards"):
        L += ["## 3. Methodology", ""]
        if d.get("method"): L += [d["method"], ""]
        if d.get("standards"): L += [f"**Standards:** {d['standards']}", ""]
    cov = d.get("coverage"); lim = d.get("limitations")
    if cov or lim or d.get("asvs_level") or d.get("compliance"):
        L += ["## 4. Standards coverage & limitations", ""]
        if d.get("asvs_level"): L += [f"**ASVS target:** {d['asvs_level']}", ""]
        if cov:
            L += ["**Coverage matrix (OWASP WSTG / ASVS / API Top 10):**", "",
                  "| Area | Status | Notes |", "|---|---|---|"]
            L += [f"| {c.get('area','')} | {c.get('status','')} | {c.get('notes','')} |" for c in cov]
            L.append("")
        if lim:
            L += ["**Coverage limitations** (a skipped test is a stated gap, not a clean result):", ""]
            L += [f"- {x}" for x in lim]; L.append("")
        if d.get("compliance"): L += [f"**Compliance mapping:** {d['compliance']}", ""]
    L += ["## 5. Findings (confirmed — severity ordered)", "", "---", ""]
    fs = sorted_findings(d)
    if fs:
        for f in fs: L += render_finding_md(f)
    else:
        L += ["_No confirmed findings._", ""]
    info = d.get("informational", [])
    if info:
        L += ["## 6. Informational / hardening", ""]
        for i in info:
            L += [f"### {i.get('id','')} — {i.get('title','')}", ""]
            if i.get("cwe"): L.append(f"**Class:** {i['cwe']}  ")
            L.append("")
            if i.get("description"): L += [i["description"], ""]
            if i.get("remediation"): L += [f"**Remediation:** {i['remediation']}", ""]
            if i.get("evidence"): L += [f"**Evidence:** `{i['evidence']}`", ""]
            L += ["---", ""]
    leads = d.get("leads", [])
    if leads:
        L += ["## 7. Leads (unconfirmed — for follow-up)", ""]
        for l in leads:
            L += [f"### {l.get('id','')} — {l.get('title','')}", ""]
            if l.get("basis"): L += [f"**Basis:** {l['basis']}", ""]
            if l.get("followup"): L += [f"**Follow-up:** {l['followup']}", ""]
            L += ["---", ""]
    ev = d.get("evidence_index", [])
    if ev:
        L += ["## 8. Appendix — evidence index", "", "| File | Contents | Ref |", "|---|---|---|"]
        L += [f"| `{x.get('file','')}` | {x.get('contents','')} | {x.get('ref','')} |" for x in ev]
        L.append("")
    L += ["---", "", "*Testing was conducted under the engagement's recorded authorization and rules "
          "of engagement. Credentials/secrets redacted; only low-sensitivity, already-public enumeration identifiers retained as finding evidence. Generated from "
          "`findings.json` (single source).*"]
    return "\n".join(L)

# ===================== CLI =====================

def main():
    args, pos, theme, fmt = sys.argv[1:], [], None, "html"
    embed_evidence = True
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--theme" and i + 1 < len(args): theme = args[i + 1].lower(); i += 2; continue
        if a.startswith("--theme="): theme = a.split("=", 1)[1].lower(); i += 1; continue
        if a == "--light": theme = "light"; i += 1; continue
        if a == "--dark": theme = "dark"; i += 1; continue
        if a == "--md": fmt = "md"; i += 1; continue
        if a == "--all": fmt = "all"; i += 1; continue
        if a == "--no-embed-evidence": embed_evidence = False; i += 1; continue
        if a == "--embed-evidence": embed_evidence = True; i += 1; continue
        pos.append(a); i += 1
    if not pos:
        print("usage: python render_report.py <findings.json> [output] [--theme dark|light] "
              "[--md|--all] [--no-embed-evidence]"); sys.exit(2)
    src = pos[0]
    with open(src, encoding="utf-8") as fh:
        raw = fh.read()
    # redaction chokepoint: never render a CREDENTIAL into a deliverable (refuse).
    # PII (emails / contact + remediation addresses) is ADVISORY — a report legitimately
    # carries them and the qa-gate treats PII as advisory (BLOCK only with --strict), so a
    # PII hit in the author-written findings.json is a note, NOT a refuse. Embedded raw
    # evidence text is still PII-neutralized on the way into report.html (via _redactor).
    _checks = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "checks")
    sys.path.insert(0, _checks)
    _redactor = None
    try:
        from redact import redact_text as _redactor, scan_file as _scan_file
        _hits = _scan_file(src)
        _secret = [h for h in _hits if h.get("category") == "secret"]
        _pii = [h for h in _hits if h.get("category") == "pii"]
        if _secret:
            print(f"REFUSING TO RENDER: findings.json contains {len(_secret)} credential-pattern hit(s). "
                  f"Run: python tools/checks/redact.py scan {src} — then redact and retry.")
            sys.exit(4)
        if _pii:
            print(f"note: {len(_pii)} advisory PII hit(s) in findings.json (e.g. a contact/remediation "
                  f"address) rendered as-is; embedded evidence PII is redacted on the way in.")
    except ImportError:
        pass
    d = json.loads(raw)
    # stamp a STABLE cross-engagement finding_uid on each finding (the lifecycle/retest
    # reference shown in the report) — computed from target+CWE+normalized-location so it
    # survives object-id/title changes across runs. (tools/checks/finding_ledger.py.)
    try:
        from finding_ledger import finding_uid as _fuid
        _tgt = (d.get("engagement", {}) or {}).get("target", "")
        for _f in d.get("findings", []) or []:
            _f.setdefault("finding_uid", _fuid(_tgt, _f.get("cwe"), _f.get("location")))
    except ImportError:
        pass
    # counts drift check: WARN (don't fail) if the declared counts disagree with the
    # actual findings — the rendered scoreboard uses the derived counts either way.
    _declared = d.get("counts")
    if _declared:
        _actual = compute_counts(d)
        _drift = {s: (_declared.get(s, 0), _actual[s]) for s in SEV_ORDER
                  if _declared.get(s, 0) != _actual[s]}
        if _drift:
            print("counts drift (declared -> rendered): " +
                  ", ".join(f"{s}={a}->{b}" for s, (a, b) in _drift.items()))
    base = os.path.dirname(os.path.abspath(src))
    # client logo (optional): base64-inline an engagement.logo image (path relative to the
    # engagement dir) so render_html can show it in the brand slot instead of the monogram.
    _eng = d.get("engagement", {}) or {}
    if _eng.get("logo"):
        _lp = _eng["logo"]
        _lp = _lp if os.path.isabs(_lp) else os.path.join(base, _lp)
        try:
            import base64 as _b64
            _ext = os.path.splitext(_lp)[1].lower().lstrip(".")
            _mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                     "gif": "image/gif", "svg": "image/svg+xml", "webp": "image/webp"}.get(_ext, "image/png")
            with open(_lp, "rb") as _lf:
                _data = _b64.b64encode(_lf.read()).decode("ascii")
            d.setdefault("engagement", {})["_logo_datauri"] = f"data:{_mime};base64,{_data}"
        except Exception as _e:
            print(f"  logo: could not read {_eng.get('logo')}: {_e}")
    here = os.path.dirname(os.path.abspath(__file__))
    theme = theme or (d.get("engagement", {}) or {}).get("theme") or "dark"
    if theme not in ("dark", "light"): theme = "dark"

    def css_for(t):
        p = os.path.join(here, "report-light.css" if t == "light" else "report.css")
        return open(p, encoding="utf-8").read() if os.path.exists(p) else ""

    # one embedder per render — fresh anchor map; redactor neutralizes embedded text
    def make_embed():
        return Evidence(base, redactor=_redactor) if embed_evidence else None

    written, embedders = [], []
    if fmt in ("md", "all"):
        out = pos[1] if (fmt == "md" and len(pos) > 1) else os.path.join(base, "report.md")
        with open(out, "w", encoding="utf-8") as fh: fh.write(render_markdown(d))
        written.append(out)
    if fmt in ("html", "all"):
        emb = make_embed(); embedders.append(emb)
        if fmt == "all":
            # dark HTML + markdown only; the light/print theme is opt-in via --theme light
            out = os.path.join(base, "report.html")
            with open(out, "w", encoding="utf-8") as fh: fh.write(render_html(d, css_for("dark"), emb))
            written.append(out)
        else:
            out = pos[1] if len(pos) > 1 else os.path.join(base, "report-light.html" if theme == "light" else "report.html")
            with open(out, "w", encoding="utf-8") as fh: fh.write(render_html(d, css_for(theme), emb))
            written.append(out)

    fs, info, leads = sorted_findings(d), d.get("informational", []), d.get("leads", [])
    emb = next((x for x in embedders if x), None)
    tail = ""
    if emb:
        tail = f" (embedded {len(emb.anchor)} evidence artifacts inline)"
        for w in emb.warnings:
            print(f"  evidence-embed: {w}")
    elif embed_evidence is False and fmt in ("html", "all"):
        tail = " (evidence NOT embedded — --no-embed-evidence; artifacts ship separately)"
    print(f"rendered {len(fs)} findings / {len(info)} info / {len(leads)} leads -> "
          + ", ".join(os.path.basename(w) for w in written) + tail)

if __name__ == "__main__":
    main()
