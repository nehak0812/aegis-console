import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ResponsiveSunburst } from '@nivo/sunburst'
import { useApi } from '../lib/api'
import { useRange } from '../App'
import { PageSources } from '../components/ui'
import { Card, Stat, Empty, SourceLink, When, Legend, Sev, Table } from '../components/ui'
import { day, compact } from '../lib/format'

const RANKV: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }

function AIStack({ st }: { st: any }) {
  const nav = useNavigate()
  if (!st) return null
  const products = new Set((st.kev || []).map((k: any) => k.ai_product))
  return (
    <div className="stack" style={{ gap: 14, marginBottom: 14 }}>
      <div className="grid g4">
        <Stat label={`AI CVEs newly in CISA KEV · ${st.window}d`} value={(st.kev || []).length}
          hint={`${st.kev_all ?? '—'} all time${products.size ? ` · ${[...products].slice(0, 3).join(', ')}` : ''}`} />
        <Stat label="Organisations with AI exposure" value={st.orgs_with_findings || 0} hint="a Medium or higher AI-risk finding" />
        <Stat label="AI package advisories" value={(st.advisories || []).length} hint="OSV.dev · last 120 days" />
        <Stat label="Use generative-AI services" value={(st.providers || []).map((p: any) => `${p.vendor} ${p.n}`).join(' · ') || '—'} hint="organisations, from DNS verification records" />
      </div>
      <div className="grid g-main-side">
        <Card title="AI exposure across the watchlist" sub={`Medium and above, with the rule behind each · ${(st.findings || []).filter((f: any) => f.severity === 'low').length} Low inventory findings (AI services in DNS, AI hostnames) are on each entity view`}>
          <Table rows={(st.findings || []).filter((f: any) => f.severity !== 'low')} max={200} onRow={(f: any) => nav(`/orgs/${f.org_id}`)} empty="No Medium or higher AI-risk finding: no exposed AI service or exploited AI product on the scanned hosts." cols={[
            { key: 'severity', label: 'Level', render: (f: any) => <Sev level={f.severity} rule={f.rule_id} />, sort: (f: any) => RANKV[f.severity] },
            { key: 'org', label: 'Organisation' },
            { key: 'title', label: 'Finding', render: (f: any) => <><div>{f.title}</div><div className="muted clamp2" style={{ fontSize: 12 }}>{f.detail}</div></> },
            { key: 'rule_id', label: 'Rule', render: (f: any) => <span className="mono" style={{ whiteSpace: 'nowrap', fontSize: 11.5 }}>{f.rule_id}</span> }]} />
        </Card>
        <div className="stack" style={{ gap: 14 }}>
          <Card title="AI findings by rule">
            {Object.keys(st.findings_by_rule || {}).length ? <HBar data={Object.entries(st.findings_by_rule).map(([r, n]) => ({ r, n })).sort((a: any, b: any) => b.n - a.n)} label="r" value="n" /> : <Empty>None yet.</Empty>}
          </Card>
          <Card title="AI & agentic themes" sub="reporting in the selected window · click to read">
            {(st.themes || []).length ? <HBar data={st.themes} label="theme" value="n" onClick={d => nav(`/analyst?topic=${encodeURIComponent(d.theme)}`)} /> : <Empty>None yet.</Empty>}
          </Card>
        </div>
      </div>
      <div className="grid g2">
        <Card title="Exploited AI software" sub={`CISA KEV entries for AI / LLM products added in the last ${st.window} days · ${st.kev_all ?? '—'} all time`} right={<SourceLink url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" label="CISA KEV" />}>
          <Table rows={st.kev || []} max={30} empty="No AI product was added to CISA KEV in this window." cols={[
            { key: 'cve', label: 'CVE', render: (v: any) => <SourceLink url={`https://nvd.nist.gov/vuln/detail/${v.cve}`} label={v.cve} /> },
            { key: 'ai_product', label: 'Product', render: (v: any) => <><b>{v.ai_product}</b><div className="muted" style={{ fontSize: 12 }}>{v.name}</div></> },
            { key: 'severity', label: 'Level', render: (v: any) => <Sev level={v.severity} rule={v.severity_rule} />, sort: (v: any) => RANKV[v.severity] },
            { key: 'kev_added', label: 'Added', render: (v: any) => day(v.kev_added) },
            { key: 'ransomware', label: 'Ransomware', render: (v: any) => (v.ransomware === 'Known' ? <span className="pill">Known</span> : '') }]} />
        </Card>
        <Card title="AI package advisories" sub="OSV.dev · LiteLLM, Langflow, MLflow, Ray, vLLM, Gradio, MCP SDK, n8n, Ollama …">
          {Object.keys(st.advisories_by_package || {}).length > 0 && <HBar data={Object.entries(st.advisories_by_package).map(([p, n]) => ({ p, n })).sort((a: any, b: any) => b.n - a.n).slice(0, 8)} label="p" value="n" />}
          <Table rows={st.advisories || []} max={40} empty="Collecting advisories…" cols={[
            { key: 'id', label: 'Advisory', render: (a: any) => <SourceLink url={a.url} label={a.cves?.[0] || a.id} /> },
            { key: 'package', label: 'Package', render: (a: any) => <span className="mono">{a.package}</span> },
            { key: 'severity', label: 'Severity', render: (a: any) => (a.severity ? <span className="pill">{a.severity}</span> : '') },
            { key: 'published', label: 'Published', render: (a: any) => day(a.published) },
            { key: 'summary', label: 'Summary', render: (a: any) => <span className="muted clamp2">{a.summary}</span> }]} />
        </Card>
      </div>
      <div className="grid g2">
        <Card title="MITRE ATLAS techniques in the reporting" sub={`reporting tagged by transparent phrase rules · ATLAS ${st.atlas?.release || '(loading)'} · ${st.atlas?.techniques || 0} techniques`} right={<SourceLink url="https://atlas.mitre.org/" label="MITRE ATLAS" />}>
          {(st.atlas?.tagged || []).length ? <HBar data={st.atlas.tagged.map((t: any) => ({ ...t, label: `${t.id} ${t.name}` }))} label="label" value="n" onClick={d => d.url && window.open(d.url, '_blank', 'noopener')} /> : <Empty>No tagged reporting yet.</Empty>}
          {(st.atlas?.case_studies || []).length > 0 && (
            <>
              <div className="muted" style={{ fontSize: 12, margin: '10px 0 4px' }}>Newest ATLAS case studies</div>
              <div className="feed">{st.atlas.case_studies.slice(0, 5).map((c: any) => (
                <div key={c.id} className="feed-item"><span className="pill mono">{c.id}</span><div><div className="t">{c.name}</div><div className="m"><span>{c.date}</span></div></div><SourceLink url={c.url} /></div>))}</div>
            </>)}
        </Card>
        <Card title="AI-vendor threat & misuse reports" sub="Anthropic, OpenAI, Google Threat Intelligence">
          <div className="feed">
            {!(st.vendor_reports || []).length && <Empty>Collecting…</Empty>}
            {(st.vendor_reports || []).slice(0, 14).map((i: any) => (
              <div key={i.id} className="feed-item"><span className="pill">{i.publisher}</span><div><div className="t">{i.title}</div><div className="m"><When ts={i.published} /></div></div><SourceLink url={i.url} /></div>))}
          </div>
        </Card>
      </div>
      <div className="grid g2">
        <Card title="AI-themed malicious packages & AI bug-bounty CVEs" sub="GitHub malware advisories (npm, PyPI) · NVD, huntr CNA (60 days)">
          <Table rows={st.malware || []} max={12} empty="No AI-themed malicious package in the latest advisories (or GitHub's anonymous rate limit — set GITHUB_TOKEN)." cols={[
            { key: 'published', label: 'Date', render: (m: any) => day(m.published) },
            { key: 'packages', label: 'Package', render: (m: any) => <span className="mono">{(m.packages || []).join(', ')}</span> },
            { key: 'url', label: '', render: (m: any) => <SourceLink url={m.url} label={m.id} /> }]} />
          <div style={{ height: 10 }} />
          <Table rows={st.huntr || []} max={12} empty="No huntr-sourced CVEs in 60 days." cols={[
            { key: 'cve', label: 'CVE', render: (h: any) => <SourceLink url={h.url} label={h.cve} /> },
            { key: 'cvss', label: 'CVSS', num: true },
            { key: 'summary', label: 'Summary', render: (h: any) => <span className="muted clamp2">{h.summary}</span> }]} />
        </Card>
        <Card title="Offensive AI agent frameworks" sub="context only — public GitHub metadata, never used to rate an organisation">
          <Table rows={st.offensive || []} empty="Collecting (GitHub's anonymous limit is 60 calls per hour — set GITHUB_TOKEN)." cols={[
            { key: 'repo', label: 'Repository', render: (r: any) => <><SourceLink url={r.url} label={r.repo} />{r.note && <div className="muted" style={{ fontSize: 11.5 }}>{r.note}</div>}</> },
            { key: 'stars', label: 'Stars', num: true, render: (r: any) => compact(r.stars) },
            { key: 'delta', label: 'Δ since last day', num: true, render: (r: any) => (r.prev_stars != null && r.stars != null ? (r.stars - r.prev_stars >= 0 ? '+' : '') + (r.stars - r.prev_stars) : '—'), sort: (r: any) => (r.stars || 0) - (r.prev_stars || r.stars || 0) },
            { key: 'pushed', label: 'Last push', render: (r: any) => day(r.pushed) }]} />
        </Card>
      </div>
    </div>
  )
}
import { HBar, Columns } from '../components/charts'
import { SERIES, nivoTheme, SURFACE, onFill } from '../lib/chartTheme'

export default function AIRisk() {
  const { range } = useRange()
  const { data } = useApi<any>(`/ai?days=${range}`, 600)
  const [sel, setSel] = useState<string | null>(null)
  const mit = data?.mit
  const sun = useMemo(() => mit?.domains ? ({ id: 'MIT', children: mit.domains.map((d: any, i: number) => ({ id: `${d.id}. ${d.name}`, color: SERIES[i % SERIES.length], children: d.subdomains.map((s: any) => ({ id: `${s.id} ${s.name}`, value: Math.max(1, s.risks), sub: s.id, cyber: s.cyber, color: SERIES[i % SERIES.length] })) })) }) : null, [mit])
  if (!data) return <div className="muted">Loading AI risk…</div>
  const subName: Record<string, string> = Object.fromEntries((mit?.domains || []).flatMap((d: any) => d.subdomains.map((s: any) => [s.id, s.name])))
  const incidents = sel ? data.incidents.filter((i: any) => i.entities?.mit === sel) : data.incidents
  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">AI risk</div>
          <h2>AI risk: the AI stack as attack surface, and the MIT AI Risk lens</h2>
          <p>AI/LLM software that attackers exploit (CISA KEV, OSV), self-hosted AI services exposed by monitored organisations, generative-AI providers in their DNS,
            AI-vendor misuse reports and MITRE ATLAS techniques in the reporting — then the MIT Domain Taxonomy with AI incident reports classified by transparent keyword rules.</p>
        </div>
        <div style={{ marginLeft: 'auto' }}><SourceLink url="https://airisk.mit.edu/" label="MIT AI Risk Repository" /></div>
      </div>
      <AIStack st={data.stack} />
      <div className="eyebrow" style={{ margin: '4px 0 10px' }}>MIT AI Risk Repository</div>
      <div className="grid g4" style={{ marginBottom: 14 }}>
        <Stat label="Risks catalogued by MIT" value={(mit?.total_risks || 0).toLocaleString()} hint="from 70+ frameworks" />
        <Stat label="AI incident reports" value={data.incidents.length} hint="AI Incident Database, newest" />
        <Stat label="Cyber-relevant incidents" value={data.incidents.filter((i: any) => ['2.1', '2.2', '4.1', '4.2', '4.3', '7.3'].includes(i.entities?.mit)).length} hint="privacy, security, misuse, robustness" />
        <Stat label={`AI-security reporting · ${range}d`} value={data.cyber_ai_reporting.length} hint="news & research on AI attacks / AI security" />
      </div>
      <div className="grid g-main-side" style={{ marginBottom: 14 }}>
        <Card title="MIT Domain Taxonomy" sub="size = risks catalogued per subdomain · click a subdomain to filter incidents">
          {sun ? (
            <>
              <div style={{ height: 460 }}>
                <ResponsiveSunburst data={sun as any} id="id" value="value" cornerRadius={3} borderWidth={2} borderColor={SURFACE} colors={(n: any) => n.data.color}
                  childColor={{ from: 'color', modifiers: [['brighter', 0.35]] } as any} enableArcLabels arcLabel={(n: any) => (n.depth === 2 ? n.data.sub : n.id.split('.')[0])}
                  arcLabelsSkipAngle={9} arcLabelsTextColor={((d: any) => onFill(d.color)) as any} theme={nivoTheme as any} animate motionConfig="gentle"
                  onClick={(n: any) => n.depth === 2 && setSel(sel === n.data.sub ? null : n.data.sub)}
                  tooltip={({ id, value, data: d }: any) => <div className="tip"><strong>{id}</strong><div>{value} catalogued risks{d.cyber ? ' · cyber-relevant' : ''}</div></div>} />
              </div>
              <Legend items={(mit.domains || []).map((d: any, i: number) => ({ label: `${d.id}. ${d.name}`, color: SERIES[i % SERIES.length] }))} />
            </>) : <Empty>Collecting the MIT database…</Empty>}
        </Card>
        <div className="stack" style={{ gap: 14 }}>
          <Card title="Causal taxonomy" sub="who or what causes the risk, intent, and timing">
            {mit?.causal ? Object.entries(mit.causal).map(([k, v]: any) => (
              <div key={k} style={{ marginBottom: 8 }}><div className="muted" style={{ fontSize: 12 }}>{k}</div>
                <HBar data={Object.entries(v).map(([a, n]) => ({ a, n })).sort((x: any, y: any) => y.n - x.n)} label="a" value="n" height={96} /></div>)) : <Empty>—</Empty>}
          </Card>
        </div>
      </div>
      <div className="grid g-main-side" style={{ marginBottom: 14 }}>
        <Card title={sel ? `AI incidents — ${sel} ${subName[sel] || ''}` : 'Latest AI incident reports'} sub="AI Incident Database · subdomain by keyword rule" right={sel && <a className="srclink" onClick={() => setSel(null)}>clear</a>}>
          <div className="feed">
            {!incidents.length && <Empty>None.</Empty>}
            {incidents.slice(0, 40).map((i: any) => (
              <div key={i.id} className="feed-item"><span className="pill" title={subName[i.entities?.mit] || ''}>{i.entities?.mit || '—'}</span>
                <div><div className="t">{i.title}</div><div className="m"><When ts={i.published} /><span>{subName[i.entities?.mit] || 'unclassified'}</span></div></div>
                <SourceLink url={i.url} /></div>))}
          </div>
        </Card>
        <Card title="Incidents by MIT subdomain">
          <HBar data={Object.entries(data.incidents_by_subdomain).map(([s, n]) => ({ s, label: s === 'Unclassified' ? s : `${s} ${subName[s] || ''}`, n })).sort((a: any, b: any) => b.n - a.n)} label="label" value="n" onClick={d => setSel(d.s === 'Unclassified' ? null : d.s)} />
        </Card>
      </div>
      <div className="grid g2">
        <Card title="AI & security reporting" sub="news and research on AI-enabled attacks, AI system security and governance">
          <div className="feed">{data.cyber_ai_reporting.slice(0, 20).map((i: any) => (
            <div key={i.id} className="feed-item"><span className="pill">{i.publisher}</span><div><div className="t">{i.title}</div><div className="m"><When ts={i.published} /></div></div><SourceLink url={i.url} /></div>))}</div>
        </Card>
        <Card title="AIAAIC repository context" sub="independent AI incident register — aggregate counts" right={<SourceLink url="https://www.aiaaic.org/aiaaic-repository" label="AIAAIC" />}>
          {data.aiaaic ? (
            <>
              <div className="muted" style={{ fontSize: 12 }}>{data.aiaaic.total?.toLocaleString()} incidents catalogued — by year</div>
              <Columns data={Object.entries(data.aiaaic.year || {}).map(([y, n]) => ({ y, n }))} x="y" y="n" height={160} />
              <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>Most affected sectors</div>
              <HBar data={Object.entries(data.aiaaic.sector || {}).map(([s, n]) => ({ s, n })).slice(0, 8)} label="s" value="n" />
            </>) : <Empty>Collecting…</Empty>}
        </Card>
      </div>
      <PageSources cats={['AI risk', 'Research', 'Threat intel']} />
    </div>
  )
}
