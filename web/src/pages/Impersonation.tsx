import { Fragment, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { ResponsiveSankey } from '@nivo/sankey'
import { ResponsiveHeatMap } from '@nivo/heatmap'
import { Download, Search, ChevronRight } from 'lucide-react'
import { useApi, qs } from '../lib/api'
import { useRange } from '../App'
import { PageSources } from '../components/ui'
import { Card, Stat, Sev, Table, Empty, SourceLink, Tabs, When, Legend } from '../components/ui'
import { HBar, Columns, StackedArea } from '../components/charts'
import { nivoTheme, SERIES, BLUE_RAMP, EMPTY, SURFACE, NEUTRAL, INK2, onFill } from '../lib/chartTheme'
import { day } from '../lib/format'

const RANKV: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }
const MATCH: Record<string, string> = { brand: 'Brand lookalike', 'own-domain': 'Own domain listed', 'own-ip': 'Own IP space', nrd: 'New lookalike', 'phish-brand': 'Phishing lookalike', 'own-site': 'Own site listed' }
const shortDay = (s: string) => new Date(s).toLocaleDateString(undefined, { day: 'numeric', month: 'short' })
const SOURCES = ['Threat-report indicator', 'Newly registered domain', 'Phishing feed', 'Malware / C2 feed']
type Tab = 'overview' | 'brand' | 'reports' | 'web' | 'context'

/** The visual overview: campaign framework, where lookalikes come from → what they pretend to be → whom, concentration and trend. */
function Visuals({ v, go }: { v: any; go: (t: Tab) => void }) {
  const nav = useNavigate()
  if (!v?.total) return <Empty>No lookalike has been matched to a monitored brand yet. Threat-report indicators, the daily new-domain list and phishing feeds fill this within a day.</Empty>
  const srcColor = (s: string) => SERIES[SOURCES.indexOf(s) % SERIES.length]
  const hmax = Math.max(1, ...v.heat.flatMap((r: any) => r.data.map((c: any) => c.y)))
  const heatColor = (n: number) => (n ? BLUE_RAMP[Math.min(BLUE_RAMP.length - 1, Math.round((Math.sqrt(n) / Math.sqrt(hmax)) * (BLUE_RAMP.length - 1)))] : EMPTY)
  const lures = new Set(v.lures.map((l: any) => l.lure))
  const sankey = { nodes: v.sankey.nodes.map((n: any) => ({ ...n, nodeColor: SOURCES.includes(n.id) ? srcColor(n.id) : lures.has(n.id) ? NEUTRAL : SERIES[6] })), links: v.sankey.links }
  return (
    <div className="stack" style={{ gap: 14 }}>
      <Card title="Impersonation campaign, stage by stage" sub="what AEGIS observes at each step, with an indicative MITRE ATT&CK mapping · click a stage to see the evidence">
        <div className="row" style={{ gap: 6, alignItems: 'stretch', overflowX: 'auto', paddingBottom: 4 }}>
          {v.framework.map((s: any, i: number) => (
            <Fragment key={i}>
              <div className="cat-tile" style={{ flex: '1 1 0', minWidth: 160 }} onClick={() => go(s.tab)}>
                <span className="eyebrow" style={{ margin: 0 }}>{s.stage}</span>
                <span className="mono muted" style={{ fontSize: 10.5 }}>{s.technique}</span>
                <b style={{ fontSize: 26, lineHeight: 1.1 }}>{Number(s.n || 0).toLocaleString()}</b>
                <span className="muted" style={{ fontSize: 12 }}>{s.what}</span>
                {s.orgs != null && <span className="pill" style={{ alignSelf: 'flex-start' }}>{s.orgs} organisation{s.orgs === 1 ? '' : 's'}</span>}
              </div>
              {i < v.framework.length - 1 && <ChevronRight size={18} style={{ alignSelf: 'center', color: 'var(--muted)', flex: '0 0 auto' }} />}
            </Fragment>))}
        </div>
      </Card>
      <div className="grid g-main-side">
        <Card title="Where lookalikes come from → what they pretend to be → whom they imitate" sub={`${v.total} lookalike domains matched to monitored brands · top 10 brands shown`}>
          <div style={{ height: 480 }}>
            <ResponsiveSankey data={sankey as any} margin={{ top: 8, right: 170, bottom: 8, left: 150 }} align="justify" colors={(n: any) => n.nodeColor}
              nodeOpacity={1} nodeThickness={14} nodeInnerPadding={2} nodeSpacing={10} nodeBorderWidth={0} linkOpacity={0.35} linkHoverOthersOpacity={0.08}
              linkBlendMode="normal" enableLinkGradient={false} labelPosition="outside" labelPadding={8} labelTextColor={INK2}
              theme={nivoTheme as any} animate motionConfig="gentle" />
          </div>
          <Legend items={[...SOURCES.filter(s => v.timeline_keys.includes(s)).map(s => ({ label: s, color: srcColor(s) })), { label: 'Lure theme', color: NEUTRAL }, { label: 'Brand', color: SERIES[6] }]} />
        </Card>
        <div className="stack" style={{ gap: 14 }}>
          <Card title="Most impersonated brands" sub="lookalike domains · click to open the brand">
            <HBar data={v.brands} label="org" value="n" onClick={(d: any) => nav(`/orgs/${d.oid}`)} />
          </Card>
          <Card title="Still resolving?" sub="public DNS check of each lookalike (never contacted)">
            <div className="grid g3" style={{ gap: 8 }}>
              <Stat label="Resolving" value={v.live.resolving} hint="web or mail set up" />
              <Stat label="Not resolving" value={v.live.not} hint="parked or taken down" />
              <Stat label="Not yet checked" value={v.live.unchecked} hint="hourly, 150 per run" />
            </div>
          </Card>
        </div>
      </div>
      <Card title="Which lures are used against which brands" sub="recurring themes: lookalike domains by brand × lure theme (from the domain's own words) · click a row to open the brand">
        <div style={{ height: Math.max(280, v.heat.length * 26 + 130) }}>
          <ResponsiveHeatMap data={v.heat} margin={{ top: 120, right: 20, bottom: 10, left: 210 }} axisTop={{ tickRotation: -35, tickSize: 0, tickPadding: 6 }} axisLeft={{ tickSize: 0, tickPadding: 8 }}
            colors={((c: any) => heatColor(c.value || 0)) as any} emptyColor={EMPTY} borderWidth={2} borderColor={SURFACE} enableLabels
            labelTextColor={((c: any) => (c.value ? onFill(heatColor(c.value)) : 'transparent')) as any} theme={nivoTheme as any} hoverTarget="cell" animate
            onClick={(c: any) => { const r = v.heat.find((h: any) => h.id === c.serieId); if (r) nav(`/orgs/${r.oid}`) }}
            tooltip={({ cell }: any) => <div className="tip"><strong>{cell.value}</strong> lookalike(s) · {cell.serieId}<div>{cell.data.x}</div></div>} />
        </div>
      </Card>
      <div className="grid g2">
        <Card title="Lookalikes over time" sub="12 weeks, by source (registration or publication date)">
          <StackedArea data={v.timeline} keys={v.timeline_keys} xKey="week" height={230} colors={v.timeline_keys.map((k: string) => srcColor(k))} />
        </Card>
        <Card title="Lure themes" sub="what the lookalikes pretend to be">
          <HBar data={v.lures} label="lure" value="n" />
        </Card>
      </div>
      <div className="grid g3">
        <Card title="Top-level domains used" sub="concentration of lookalike registrations"><HBar data={v.tlds} label="tld" value="n" /></Card>
        <Card title="Where lookalikes are hosted" sub="name-server provider of resolving lookalikes (takedown contacts)">
          {v.hosting.length ? <HBar data={v.hosting} label="ns" value="n" /> : <Empty>Liveness checks still running.</Empty>}
        </Card>
        <Card title="Who reports them" sub="publishers whose indicators imitate monitored brands">
          {v.reporters.length ? <HBar data={v.reporters} label="publisher" value="n" /> : <Empty>None yet.</Empty>}
        </Card>
      </div>
    </div>
  )
}

function FindingTable({ rows, empty }: { rows: any[]; empty: string }) {
  const nav = useNavigate()
  return (
    <Table rows={rows} onRow={(f: any) => nav(`/orgs/${f.org_id}`)} empty={empty} max={300} cols={[
      { key: 'severity', label: 'Level', render: (f: any) => <Sev level={f.severity} rule={f.rule_id} />, sort: (f: any) => RANKV[f.severity] },
      { key: 'org', label: 'Organisation' },
      { key: 'title', label: 'Finding', render: (f: any) => <><div>{f.title}</div><div className="muted clamp2" style={{ fontSize: 12 }}>{f.detail}</div></> },
      { key: 'rule_id', label: 'Rule', render: (f: any) => <span className="mono" style={{ whiteSpace: 'nowrap', fontSize: 11.5 }}>{f.rule_id}</span> },
      { key: 'first_seen', label: 'First seen', render: (f: any) => <When ts={f.first_seen} /> },
      { key: 'evidence_url', label: '', render: (f: any) => (f.evidence_url?.startsWith('http') ? <SourceLink url={f.evidence_url} /> : null) },
    ]} />
  )
}

function Feed({ rows, empty }: { rows: any[]; empty: string }) {
  if (!rows.length) return <Empty>{empty}</Empty>
  return (
    <div className="feed">{rows.map((i: any) => (
      <div key={i.id} className="feed-item"><span className="pill">{i.publisher}</span>
        <div><div className="t">{i.title}</div><div className="m"><When ts={i.published} /></div></div><SourceLink url={i.url} /></div>))}
    </div>
  )
}

export default function Impersonation() {
  const { range } = useRange()
  const nav = useNavigate()
  const [sp, setSp] = useSearchParams()
  const q = sp.get('q') || ''
  const [term, setTerm] = useState(q)
  const [tab, setTab] = useState<Tab>('overview')
  const { data } = useApi<any>(`/impersonation${qs({ days: range, q })}`, 300)
  if (!data) return <div className="muted">Loading impersonation & indicators…</div>
  const s = data.stats
  const search = (e: React.FormEvent) => { e.preventDefault(); const n = new URLSearchParams(sp); term.trim() ? n.set('q', term.trim()) : n.delete('q'); setSp(n) }
  const lastNrd = data.nrd_stats[data.nrd_stats.length - 1]

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">Impersonation & indicators</div>
          <h2>Brand lookalikes, published indicators, and websites used against visitors</h2>
          <p>Indicators from threat reports (Anthropic, MISP OSINT, Cisco Talos, Unit 42, Meta), newly registered lookalike domains, phishing feeds and
            ClickFix listings — matched to monitored organisations by explainable rules. Lookalikes are resolved through public DNS only; nothing is contacted.</p>
        </div>
        <div style={{ marginLeft: 'auto' }}><a className="btn" href="/api/iocs/export?days=90"><Download size={13} />Hunt pack (CSV, 90 days)</a></div>
      </div>
      <div className="grid g4" style={{ marginBottom: 14 }}>
        <Stat label="Organisations with Critical / High" value={s.orgs} hint="impersonation, listed sites or DNS changes" />
        <Stat label="Brand impersonation findings" value={s.brand} hint={`${s.brand_hi} Critical or High`} />
        <Stat label={`New lookalike domains · ${s.window ?? 30}d`} value={s.nrd_window ?? s.nrd_30d} hint={lastNrd ? `${lastNrd.total?.toLocaleString()} new domains checked on ${shortDay(lastNrd.day)}` : 'awaiting the first daily list'} />
        <Stat label={`Indicators from threat reports · ${s.window ?? 30}d`} value={(s.iocs_window ?? s.iocs).toLocaleString()} hint={`${s.reports} reports in the window · ${s.iocs.toLocaleString()} indicators all time`} />
      </div>

      <Card title="Look up an indicator" sub="domain, URL or IP — is it in any ingested report or feed?">
        <form onSubmit={search} className="row" style={{ gap: 8 }}>
          <input className="txt" style={{ flex: 1 }} value={term} onChange={e => setTerm(e.target.value)} placeholder="e.g. ms365-live.com" />
          <button className="btn" type="submit"><Search size={13} />Look up</button>
        </form>
        {q && (
          <div style={{ marginTop: 10 }}>
            <Table rows={data.search} empty={`“${q}” is not in any ingested report or feed. Absence is not proof it is safe.`} cols={[
              { key: 'value', label: 'Indicator', render: (i: any) => <span className="mono">{i.value}</span> },
              { key: 'type', label: 'Type' }, { key: 'publisher', label: 'Published by' },
              { key: 'report_title', label: 'Report', render: (i: any) => <SourceLink url={i.report_url} label={i.report_title} /> },
              { key: 'published', label: 'Date', render: (i: any) => day(i.published) },
              { key: 'match', label: 'Monitored organisation', render: (i: any) => (i.org_id ? <span className="pill btn" onClick={() => nav(`/orgs/${i.org_id}`)}>{MATCH[i.match] || i.match} · {i.org_id}</span> : '') }]} />
          </div>)}
      </Card>

      <div style={{ marginTop: 14 }}>
        <Tabs value={tab} onChange={setTab} tabs={[{ id: 'overview', label: 'Overview' }, { id: 'brand', label: 'Brand impersonation', count: data.brand.length }, { id: 'reports', label: 'Threat-report indicators', count: data.reports.length },
          { id: 'web', label: 'Websites & DNS', count: data.web.length + data.dns.length }, { id: 'context', label: 'Identity & influence context' }]} />
      </div>

      {tab === 'overview' && <Visuals v={data.visuals} go={setTab} />}

      {tab === 'brand' && (
        <div className="stack" style={{ gap: 14 }}>
          <Card title="Brand impersonation across the watchlist" sub="lookalike domains in threat reports, newly registered lookalikes and live phishing · hover a level for its rule">
            <FindingTable rows={data.brand} empty="No brand impersonation found yet. The new-domain list is read daily and the phishing feeds every 6 hours." />
          </Card>
          <div className="grid g3">
            <Card title="New lookalike domains by brand" sub="WhoisDS newly registered domains · 30 days">
              {data.nrd_by_org.length ? <HBar data={data.nrd_by_org} label="org" value="n" onClick={d => nav(`/orgs/${d.org_id}`)} /> : <Empty>None matched yet.</Empty>}
            </Card>
            <Card title="Brands targeted in PhishTank" sub="verified phishing pages that are still online">
              {data.phishtank.length ? <HBar data={data.phishtank} label="org" value="n" onClick={d => nav(`/orgs/${d.org_id}`)} /> : <Empty>No monitored brand is a PhishTank target label.</Empty>}
            </Card>
            <Card title="Brand matches per day" sub="daily new-domain list (gTLD sample, ~70k domains)">
              {data.nrd_stats.length ? <Columns data={data.nrd_stats} x="day" y="matches" height={200} fmtX={shortDay} /> : <Empty>Awaiting the first daily list.</Empty>}
            </Card>
          </div>
        </div>
      )}

      {tab === 'reports' && (
        <div className="stack" style={{ gap: 14 }}>
          <Card title="Threat reports ingested" sub="indicator + short context + link only — never the report text">
            <Table rows={data.reports} max={80} empty="No reports ingested yet." cols={[
              { key: 'published', label: 'Date', render: (r: any) => day(r.published) },
              { key: 'publisher', label: 'Publisher' },
              { key: 'report_title', label: 'Report', render: (r: any) => <SourceLink url={r.report_url} label={r.report_title} /> },
              { key: 'n', label: 'Indicators', num: true },
              { key: 'matched', label: 'Touch monitored orgs', num: true, render: (r: any) => (r.matched ? <b>{r.matched}</b> : <span className="muted">0</span>) },
              { key: 'x', label: '', render: (r: any) => <a className="srclink" href={`/api/iocs/export?days=3650&report=${encodeURIComponent(r.report_url)}`} onClick={e => e.stopPropagation()}>CSV</a> }]} />
          </Card>
          <div className="grid g2">
            <Card title="Indicator types"><HBar data={Object.entries(data.types).map(([t, n]) => ({ t, n }))} label="t" value="n" /></Card>
            <Card title="Indicators by publisher"><HBar data={data.publishers} label="publisher" value="n" /></Card>
          </div>
          <Card title="Indicators that touch monitored organisations" sub="brand lookalike, own domain or own IP space — the reason is shown for every match">
            <Table rows={data.matched} max={200} onRow={(i: any) => nav(`/orgs/${i.org_id}`)} empty="No report indicator matches a monitored organisation." cols={[
              { key: 'org', label: 'Organisation' }, { key: 'value', label: 'Indicator', render: (i: any) => <span className="mono">{i.value}</span> },
              { key: 'match', label: 'Match', render: (i: any) => <span className="pill">{MATCH[i.match] || i.match}</span> },
              { key: 'how', label: 'Why', render: (i: any) => <span className="muted">{i.how}</span> },
              { key: 'live', label: 'Resolves', render: (i: any) => (i.attrs?.checked ? ((i.attrs.a || []).length || (i.attrs.mx || []).length ? <Sev level="high" compact /> : <span className="muted">no</span>) : <span className="muted">not checked</span>) },
              { key: 'report_title', label: 'Report', render: (i: any) => <SourceLink url={i.report_url} label={i.publisher} /> },
              { key: 'published', label: 'Date', render: (i: any) => day(i.published) }]} />
          </Card>
        </div>
      )}

      {tab === 'web' && (
        <div className="stack" style={{ gap: 14 }}>
          <Card title="Websites used against visitors & listed infrastructure" sub="organisation-owned hostnames or IPs listed by URLhaus, ThreatFox or threat reports"
            right={<span className="muted" style={{ fontSize: 12 }}>ClickFix / fake-CAPTCHA listings in feeds now: URLhaus {data.clickfix?.URLhaus || 0} · ThreatFox {data.clickfix?.ThreatFox || 0}</span>}>
            <FindingTable rows={data.web} empty="No organisation-owned hostname or IP appears in the malware, ClickFix or report indicator feeds. Free-hosting platforms (e.g. docs.google.com, vercel.app) are excluded so a platform owner is not blamed for abuse." />
          </Card>
          <Card title="DNS changes (possible hijack)" sub="name servers, mail exchangers, DNSSEC and CAA compared across passive scans">
            <FindingTable rows={data.dns} empty="No persistent DNS change. Detection needs three passive scans of a domain (about two days of collection) and only flags a change that persists across two consecutive scans." />
          </Card>
        </div>
      )}

      {tab === 'context' && (
        <div className="stack" style={{ gap: 14 }}>
          <div className="grid g2">
            <Card title="Identity attacks in the reporting" sub="device-code phishing, token theft, OAuth consent · context for Microsoft 365, Google and Okta tenants">
              <Feed rows={data.identity} empty="No identity-attack reporting in this window." />
            </Card>
            <Card title="Influence operations (FIMI) in the reporting" sub="EUvsDisinfo, DFRLab, AI-vendor disruption reports · organisation and brand level only">
              <Feed rows={data.influence} empty="No influence-operation reporting in this window." />
            </Card>
          </div>
          <Card title="News-style domain registrations" sub="context, not a finding · networks of fake news sites start as bursts of place + news-word domains (Anthropic, Sept 2026)">
            {data.news_domains.length ? (
              <>
                <Columns data={[...data.news_domains].reverse()} x="day" y="count" height={180} fmtX={shortDay} />
                <div className="muted" style={{ fontSize: 12, margin: '8px 0 6px' }}>Registered {shortDay(data.news_domains[0].day)} (sample):</div>
                <div className="row wrap" style={{ gap: 6 }}>{data.news_domains[0].sample.map((d: string) => <span key={d} className="pill mono">{d}</span>)}</div>
              </>) : <Empty>Awaiting the first daily new-domain list.</Empty>}
          </Card>
        </div>
      )}
      <PageSources cats={['Attack surface', 'Threat intel']} note="Lookalikes are matched passively (registration lists, DNS over HTTPS) and never contacted." />
    </div>
  )
}
