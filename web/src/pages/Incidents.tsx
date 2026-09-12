import { useMemo, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { ResponsiveNetwork } from '@nivo/network'
import { ResponsiveTreeMap } from '@nivo/treemap'
import { motion, AnimatePresence } from 'motion/react'
import { Network, Boxes, Search } from 'lucide-react'
import { useApi, qs } from '../lib/api'
import { useRange } from '../App'
import { Card, Sev, Why, Empty, When, SourceLink, Tabs, Seg, Table, SevCounts, Stat, Legend } from '../components/ui'
import { HBar, SpreadTimeline } from '../components/charts'
import { ResponsiveHeatMap } from '@nivo/heatmap'
import { StoryStrip, SectionLabel, PageSources } from '../components/ui'
import { StackedBars } from '../components/summaryviz'
import * as CT from '../lib/chartTheme'
import { nivoTheme, SEV_COLOR, SERIES, NEUTRAL, SURFACE, INK, onFill } from '../lib/chartTheme'
import { day, pct } from '../lib/format'
import { api } from '../lib/api'

// resolved on read so the active theme's palette applies
const LT_COLOR: Record<string, string> = new Proxy({} as Record<string, string>, {
  get: (_t, k: string) => ({ DIRECT: SERIES[7], GROUP: SERIES[6], DEPENDENCY: SERIES[0], EXPOSED_PRODUCT: SERIES[1], NAMED_CUSTOMER: SERIES[4], TARGETING: NEUTRAL } as Record<string, string>)[k],
})
const LT_ORDER = ['DIRECT', 'GROUP', 'EXPOSED_PRODUCT', 'DEPENDENCY', 'NAMED_CUSTOMER', 'TARGETING']
const LT_CHIP: Record<string, string> = { EXPOSED_PRODUCT: 'exposed', NAMED_CUSTOMER: 'named customer', DEPENDENCY: 'uses provider' }

function ImpactChips({ impacts, types }: { impacts: Record<string, number>; types: Record<string, string> }) {
  return (
    <span className="row wrap" style={{ gap: 4 }}>
      {LT_ORDER.filter(k => impacts?.[k]).map(k => (
        <span key={k} className="pill" title={types[k]}><span className="dot" style={{ background: LT_COLOR[k] }} />{impacts[k]} {LT_CHIP[k] || k.toLowerCase()}</span>
      ))}
    </span>
  )
}

function Detail({ id }: { id: string }) {
  const nav = useNavigate()
  const { data } = useApi<any>(`/incidents/${id}`, 120)
  const [view, setView] = useState<'graph' | 'table'>('graph')
  if (!data) return <Card><div className="muted">Loading incident…</div></Card>
  const byType = LT_ORDER.map(k => ({ type: k, label: data.link_types[k], n: data.by_type?.[k] || 0 })).filter(r => r.n)
  return (
    <motion.div key={id} initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} className="stack" style={{ gap: 14 }}>
      <Card>
        <div className="row wrap" style={{ gap: 8, marginBottom: 6 }}>
          <Sev level={data.severity} rule={data.severity_rule} /><span className="pill">{data.kind}</span>
          <span className="muted" style={{ fontSize: 12 }}>First seen {day(data.first_seen)} · last {day(data.last_seen)} · {data.source_count} independent source{data.source_count === 1 ? '' : 's'}</span>
          {data.spread?.spreading && <span className="pill" title="3+ independent publishers within 72 hours of the first report">spreading · {data.spread.publishers_72h} publishers in 72h</span>}
          {data.velocity?.kev_lag != null && <span className="pill" title="CVE publication → CISA KEV addition">{data.velocity.kev_lag <= 0 ? 'zero-day: exploited at or before disclosure' : `exploited ${data.velocity.kev_lag} days after disclosure`}</span>}
        </div>
        <h2 style={{ margin: '4px 0 10px', fontSize: 20 }}>{data.title}</h2>
        <Why rule={data.severity_rule} level={data.severity} />
        <div className="row wrap" style={{ gap: 6, marginTop: 10 }}>
          {data.victim_org_id && <span className="pill btn accent" onClick={() => nav(`/orgs/${data.victim_org_id}`)}>Victim: {data.victim}</span>}
          {data.actor_profiles?.map((a: any) => <span key={a.id} className="pill btn" onClick={() => nav(`/adversaries/${a.id}`)}>Actor: {a.name}{a.crowdstrike ? ` (${a.crowdstrike})` : ''}</span>)}
          {data.actors?.filter((a: string) => !data.actor_profiles?.some((p: any) => p.name.toLowerCase() === a.toLowerCase())).map((a: string) => <span key={a} className="pill">Actor: {a}</span>)}
          {data.vendors?.map((v: string) => <span key={v} className="pill btn" onClick={() => nav(`/incidents?provider=${encodeURIComponent(v)}`)}>Vendor: {v}</span>)}
          {data.cves?.map((c: string) => <a key={c} className="pill btn mono" href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer">{c} ↗</a>)}
        </div>
      </Card>

      <Card title="Who could be impacted" sub={`${data.impacts.length} organisation link${data.impacts.length === 1 ? '' : 's'} · every link carries its evidence`}
        right={<Seg options={[{ id: 'graph', label: 'Graph' }, { id: 'table', label: 'List' }]} value={view} onChange={setView} />}>
        {data.impacts.length === 0 ? (
          <Empty>No monitored organisation is linked to this incident by the six linkage rules (victim, corporate group, provider dependency, named customer, exposed product, sector targeting). The victim may be outside the monitored universe, or the provider may not be visible in public DNS — add its DNS evidence under Provider concentration.</Empty>
        ) : view === 'graph' ? (
          <div className="grid" style={{ gridTemplateColumns: 'minmax(0,1fr) 230px' }}>
            <div style={{ height: 460 }}>
              <ResponsiveNetwork
                data={data.graph as any}
                margin={{ top: 10, right: 10, bottom: 10, left: 10 }}
                linkDistance={(l: any) => (String(l.source?.id || l.source).startsWith('lt-') ? 70 : 90)}
                centeringStrength={0.5}
                repulsivity={14}
                iterations={120}
                // nivo passes raw node data to the accessors and a computed node (with .data) to events — accept both
                nodeSize={(n: any) => { const d = n.data ?? n; return d.type === 'incident' ? 26 : d.type === 'link' ? 14 : 10 }}
                activeNodeSize={(n: any) => { const d = n.data ?? n; return d.type === 'incident' ? 30 : 16 }}
                nodeColor={(n: any) => { const d = n.data ?? n; return d.type === 'link' ? LT_COLOR[String(d.id).replace('lt-', '')] : SEV_COLOR[d.level] || SERIES[0] }}
                nodeBorderWidth={2}
                nodeBorderColor={SURFACE}
                linkThickness={1.5}
                linkColor={{ from: 'target.color', modifiers: [['opacity', 0.35]] } as any}
                motionConfig="gentle"
                theme={nivoTheme as any}
                onClick={(n: any) => (n.data ?? n).type === 'org' && nav(`/orgs/${n.id}`)}
                nodeTooltip={({ node }: any) => { const d = node.data ?? node; return (
                  <div className="tip"><strong>{d.label}</strong>{d.type === 'org' && <div>{d.sector || ''} · {d.level}</div>}{d.type === 'org' && <div className="muted">click to open</div>}</div>
                ) }}
              />
            </div>
            <div className="stack">
              <div className="muted" style={{ fontSize: 12 }}>How organisations are linked</div>
              {byType.map(r => (
                <div key={r.type} className="row" style={{ fontSize: 12.5 }}>
                  <span className="dot" style={{ background: LT_COLOR[r.type], width: 10, height: 10 }} /><span style={{ flex: 1 }}>{r.label}</span><b>{r.n}</b>
                </div>
              ))}
              <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>Nodes are coloured by the level of the link: <span style={{ color: SEV_COLOR.critical }}>critical</span>, <span style={{ color: SEV_COLOR.high }}>high</span>, <span style={{ color: SEV_COLOR.medium }}>medium</span>, grey = low.</div>
              <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>By sector</div>
              <HBar data={Object.entries(data.by_sector).map(([s, n]) => ({ s, n })).sort((a: any, b: any) => b.n - a.n).slice(0, 8)} label="s" value="n" />
            </div>
          </div>
        ) : (
          <Table rows={data.impacts} onRow={(r: any) => nav(`/orgs/${r.org_id}`)} initialSort={['severity', 'asc']}
            cols={[
              { key: 'severity', label: 'Level', render: (r: any) => <Sev level={r.severity} />, sort: (r: any) => ['critical', 'high', 'medium', 'low'].indexOf(r.severity) },
              { key: 'name', label: 'Organisation', render: (r: any) => <><b>{r.name}</b><div className="muted" style={{ fontSize: 12 }}>{r.sector} · {r.country}</div></> },
              { key: 'link_type', label: 'Link', render: (r: any) => <span className="row"><span className="dot" style={{ background: LT_COLOR[r.link_type] }} />{data.link_types[r.link_type]}</span> },
              { key: 'reason', label: 'Why', render: (r: any) => <span className="ink2" style={{ fontSize: 12.5 }}>{r.reason}<div className="muted mono" style={{ fontSize: 11 }}>{String(r.evidence).startsWith('http') ? <SourceLink url={r.evidence} /> : r.evidence}</div></span> },
            ]} />
        )}
      </Card>

      {data.vulns?.length > 0 && (
        <Card title="Exploited vulnerabilities in this incident">
          <Table rows={data.vulns} cols={[
            { key: 'cve', label: 'CVE', render: (v: any) => <SourceLink url={`https://nvd.nist.gov/vuln/detail/${v.cve}`} label={v.cve} /> },
            { key: 'severity', label: 'Level', render: (v: any) => <Sev level={v.severity} rule={v.severity_rule} /> },
            { key: 'vendor', label: 'Product', render: (v: any) => `${v.vendor || ''} ${v.product || ''}` },
            { key: 'epss', label: 'EPSS', num: true, render: (v: any) => pct(v.epss) },
            { key: 'kev_added', label: 'KEV added', render: (v: any) => v.kev_added || '—' },
          ]} />
        </Card>
      )}

      {(data.spread?.publishers || 0) >= 2 && (
        <Card title="How fast it spread" sub="each independent publisher, in the order they reported it" right={<a className="srclink" onClick={() => nav('/speed')}>Speed & spread →</a>}>
          <SpreadTimeline curve={data.spread.curve} />
        </Card>)}

      <Card title="Source trail" sub="every report that built this incident, oldest → newest">
        <div className="feed">
          {(data.sources || []).slice().reverse().map((s: any, i: number) => (
            <div key={i} className="feed-item">
              <span className="pill">{s.type}</span>
              <div><div className="t clamp2">{s.title}</div><div className="m"><span>{s.publisher}</span><When ts={s.published} /></div></div>
              {s.url?.startsWith('http') ? <SourceLink url={s.url} /> : <span />}
            </div>
          ))}
        </div>
      </Card>
    </motion.div>
  )
}

const EMPTY_FORM = { name: '', category: '', aliases: '', cname: '', txt: '', spf: '', mx: '' }

function Providers() {
  const nav = useNavigate()
  const { range } = useRange()
  const { data, refetch } = useApi<any>(`/linkage/providers?days=${range}`, 300)
  const { data: cat, refetch: refetchCat } = useApi<any>('/providers', 600)
  const [q, setQ] = useState('')
  const [form, setForm] = useState<any>(EMPTY_FORM)
  const [msg, setMsg] = useState('')
  if (!data) return <div className="muted">Loading…</div>
  const cats = Object.keys(data.categories)
  const catColor = (c: string) => SERIES[Math.max(0, cats.indexOf(c)) % SERIES.length]
  const grouped = data.providers.filter((p: any) => p.n > 0).reduce((acc: any, p: any) => { (acc[p.category] ||= []).push(p); return acc }, {})
  const tree = { id: 'providers', children: Object.entries(grouped).map(([c, ps]: any) => ({ id: c, children: ps.slice(0, 16).map((p: any) => ({ id: p.vendor, value: p.n, worst: p.worst, cat: c, named: p.named, inc: p.incidents.length })) })) }
  const set = (k: string) => (e: any) => setForm({ ...form, [k]: e.target.value })
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const r = await api('/providers', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) })
      setMsg(`Saved “${r.name}”. The pipeline is re-running now: its patterns are applied to every stored scan and its incidents are linked — refreshing in 30 seconds.`)
      setForm(EMPTY_FORM)
      setTimeout(() => { refetch(); refetchCat() }, 30000)
    } catch (err: any) { setMsg(`Could not save: ${err.message || err}`) }
  }
  const del = async (name: string) => { await api(`/providers/${encodeURIComponent(name)}`, { method: 'DELETE' }); refetchCat() }
  const rows = (cat?.providers || []).filter((p: any) => !q || `${p.name} ${(p.aliases || []).join(' ')} ${p.category}`.toLowerCase().includes(q.toLowerCase()))
  const npat = (p: any) => Object.values(p.patterns || {}).reduce((a: number, v: any) => a + (v?.length || 0), 0)
  return (
    <div className="stack" style={{ gap: 14 }}>
      <div className="grid g4">
        <Stat label="Providers recognised" value={data.catalogue_size} hint="shipped catalogue + analyst additions" />
        <Stat label="Seen in the watchlist's DNS" value={data.providers.filter((p: any) => p.n > 0).length} hint={`across ${data.scanned_orgs} scanned organisations`} />
        <Stat label="Providers with an issue now" value={data.active.length} hint={`breach, compromise, outage or exploited product · last ${range} days`} />
        <Stat label="…of which invisible in DNS" value={data.unobserved_with_issues.length}
          hint={data.unobserved_with_issues.length ? `${data.unobserved_with_issues.slice(0, 3).join(' · ')} — reach via named customers` : 'every provider with an issue is evidenced in DNS'} />
      </div>
      <div className="grid g-main-side">
        <Card title="Provider concentration" sub="third parties shared across the watchlist (public DNS), by category · outline = active issue, in its level's colour · click to see the organisations that use it">
          <div style={{ height: 520 }}>
            <ResponsiveTreeMap data={tree as any} identity="id" value="value" leavesOnly innerPadding={2} outerPadding={2}
              label={(n: any) => `${n.id} · ${n.value}`} labelSkipSize={36}
              colors={(n: any) => catColor(n.data.cat)}
              nodeOpacity={0.85} borderWidth={3} borderColor={((n: any) => (n.data?.worst ? SEV_COLOR[n.data.worst] : SURFACE)) as any}
              labelTextColor={((n: any) => onFill(n.color)) as any} parentLabelTextColor={INK} theme={nivoTheme as any} animate motionConfig="gentle"
              onClick={(n: any) => nav(`/orgs?provider=${encodeURIComponent(n.id)}`)}
              tooltip={({ node }: any) => <div className="tip"><strong>{node.id}</strong><div>{node.value} monitored organisations · {node.data.cat}</div>
                {node.data.named > 0 && <div>{node.data.named} named as customers in reporting</div>}{node.data.worst && <div><Sev level={node.data.worst} /> {node.data.inc} active issue(s)</div>}</div>} />
          </div>
          <Legend items={cats.filter(c => grouped[c]).map(c => ({ label: c, color: catColor(c) }))} />
        </Card>
        <Card title="Providers with issues now" sub="ranked by level, then reach · click to open the incident">
          {!data.active.length ? <Empty>No provider has a breach, compromise, outage or exploited product in the last {range} days.</Empty> : (
            <div className="feed" style={{ maxHeight: 560, overflowY: 'auto' }}>{data.active.map((p: any) => (
              <div key={p.vendor} className="feed-item clickable" style={{ gridTemplateColumns: 'auto 1fr' }} onClick={() => nav(`/incidents/${p.incidents[0].id}`)}>
                <Sev level={p.worst} compact />
                <div>
                  <div className="t">{p.vendor} <span className="muted" style={{ fontWeight: 400, fontSize: 12 }}>· {p.category}</span></div>
                  <div className="m clamp2">{p.incidents[0].title}{p.incidents.length > 1 ? ` (+${p.incidents.length - 1} more)` : ''}</div>
                  <div className="m"><span className="pill">{p.incidents[0].kind}</span><span>{p.n} org{p.n === 1 ? '' : 's'} in DNS</span>
                    {p.n > 0 && <a className="srclink" onClick={e => { e.stopPropagation(); nav(`/orgs?provider=${encodeURIComponent(p.vendor)}`) }}>see organisations</a>}
                    {p.named > 0 && <span>{p.named} named customer{p.named === 1 ? '' : 's'}</span>}
                    {p.n === 0 && <span className="pill" title="No monitored organisation shows this provider in public DNS; reach comes from organisations named in reporting">not visible in DNS</span>}
                    <When ts={p.incidents[0].last_seen} /></div>
                </div>
              </div>))}</div>)}
        </Card>
      </div>
      <div className="grid g2">
        <Card title="Reach of providers with issues" sub="monitored organisations evidenced in DNS plus those named as customers · bar colour = worst level">
          {data.active.some((p: any) => p.n + p.named > 0) ? <HBar data={data.active.filter((p: any) => p.n + p.named > 0).slice(0, 14).map((p: any) => ({ vendor: p.vendor, reach: p.n + p.named, worst: p.worst, id: p.incidents[0].id }))} label="vendor" value="reach"
            colorFn={(d: any) => SEV_COLOR[d.worst] || SERIES[0]} onClick={(d: any) => nav(`/incidents/${d.id}`)} /> : <Empty>No provider with an issue reaches a monitored organisation.</Empty>}
          {data.unobserved_with_issues.length > 0 && <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>Not visible in public DNS (reach unknown unless reporting names customers): {data.unobserved_with_issues.join(', ')} — add DNS evidence below if you have it.</div>}
        </Card>
        <Card title="Concentration by category" sub="organisation → provider links in public DNS">
          <HBar data={Object.entries(data.categories).map(([c, n]) => ({ c, n })).filter((r: any) => r.n > 0).sort((a: any, b: any) => b.n - a.n).slice(0, 14)} label="c" value="n"
            colorFn={(d: any) => catColor(d.c)} />
        </Card>
      </div>
      <div className="grid g-main-side">
        <Card title="Provider catalogue" sub="names map headlines to one provider; DNS patterns map organisations to it · analyst additions are marked"
          right={<input className="txt" placeholder="Filter providers…" value={q} onChange={e => setQ(e.target.value)} />}>
          <Table rows={rows} max={200} empty="Loading the catalogue…" cols={[
            { key: 'name', label: 'Provider', render: (p: any) => <><b>{p.name}</b><div className="muted" style={{ fontSize: 11.5 }}>{(p.aliases || []).slice(0, 4).join(' · ')}</div></> },
            { key: 'category', label: 'Category' },
            { key: 'orgs', label: 'Orgs in DNS', num: true, render: (p: any) => (p.orgs ? <a className="clickable" title="see the monitored organisations that use it" onClick={e => { e.stopPropagation(); nav(`/orgs?provider=${encodeURIComponent(p.name)}`) }}>{p.orgs}</a> : 0) },
            { key: 'patterns', label: 'DNS patterns', render: (p: any) => (p.observable ? (npat(p) ? `${npat(p)}` : <span className="muted">names only</span>) : <span className="pill" title="Public DNS cannot reveal this provider">not observable</span>), sort: (p: any) => npat(p) },
            { key: 'source', label: '', render: (p: any) => (p.source === 'analyst' ? <span className="row" style={{ gap: 6 }}><span className="pill accent">analyst</span><a className="srclink" onClick={e => { e.stopPropagation(); del(p.name) }}>remove</a></span> : null) }]} />
        </Card>
        <Card title="Add or extend a provider" sub="e.g. a data platform in the news that the catalogue misses">
          <form onSubmit={submit} className="stack" style={{ gap: 8 }}>
            <input className="txt" required placeholder="Provider name, e.g. Databricks" value={form.name} onChange={set('name')} />
            <input className="txt" list="prov-cats" placeholder="Category, e.g. Data platform" value={form.category} onChange={set('category')} />
            <datalist id="prov-cats">{(cat?.categories || []).map((c: string) => <option key={c} value={c} />)}</datalist>
            <input className="txt" placeholder="Names in headlines (comma-separated), e.g. Databricks Inc, Mosaic AI" value={form.aliases} onChange={set('aliases')} />
            <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>Optional public-DNS evidence (comma-separated, plain values or regex):</div>
            <input className="txt" placeholder="CNAME targets, e.g. cloud.databricks.com, azuredatabricks.net" value={form.cname} onChange={set('cname')} />
            <input className="txt" placeholder="TXT verification prefixes, e.g. databricks-verification=" value={form.txt} onChange={set('txt')} />
            <input className="txt" placeholder="SPF includes, e.g. _spf.example-saas.com" value={form.spf} onChange={set('spf')} />
            <input className="txt" placeholder="MX hosts, e.g. mx.example-saas.com" value={form.mx} onChange={set('mx')} />
            <button className="btn primary" type="submit" style={{ alignSelf: 'flex-start' }}>Save provider</button>
            {msg && <div className="muted" style={{ fontSize: 12.5 }}>{msg}</div>}
          </form>
          <div className="muted" style={{ fontSize: 12, marginTop: 10 }}>Existing providers are extended, not replaced. Names alone are enough to recognise the provider in incident reporting;
            organisations are then linked when they show the provider in DNS, or when reporting names them as affected customers.</div>
        </Card>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ summary band: the incidents in view, who they reach and how, and the daily tempo */
const LINK_ORDER = ['DIRECT', 'GROUP', 'NAMED_CUSTOMER', 'EXPOSED_PRODUCT', 'DEPENDENCY']
const LINK_SHORT: Record<string, string> = { DIRECT: 'Named victim', GROUP: 'Corporate group', NAMED_CUSTOMER: 'Named customer', EXPOSED_PRODUCT: 'Runs the product', DEPENDENCY: 'Uses the provider' }
function IncidentSummary({ data, range, onKind, onOpen }: { data: any; range: string; onKind: (k: string) => void; onOpen: (id: string) => void }) {
  const s = data.summary
  if (!s) return null
  const list: any[] = data.incidents
  const kinds = Object.entries(data.kinds as Record<string, number>).sort((a, b) => b[1] - a[1])
  const top = [...list].sort((a, b) => (b.impacted || 0) - (a.impacted || 0))[0]
  const cell: Record<string, Record<string, number>> = {}
  for (const m of s.matrix) (cell[m.kind] ||= {})[m.link] = m.orgs
  const cols = LINK_ORDER.filter(l => s.by_link[l])
  // empty cells are null so they render as "no link" rather than the lightest shade
  const heat = kinds.map(([k]) => ({ id: k, data: cols.map(l => ({ x: LINK_SHORT[l], y: cell[k]?.[l] || null })) })).filter(r => r.data.some(d => d.y))
  const max = Math.max(1, ...s.matrix.map((m: any) => m.orgs))
  const ramp = CT.BLUE_RAMP
  const heatColor = (v: number) => ramp[Math.min(ramp.length - 1, Math.floor((Math.log(v + 1) / Math.log(max + 1)) * (ramp.length - 1)))]
  const sev = data.severity || {}
  const h = Math.max(200, 50 + heat.length * 36)
  return (
    <>
      <StoryStrip items={[
        { label: `In view · ${range}d`, value: list.length, title: 'incidents', sub: `${sev.critical || 0} critical · ${s.spreading} spreading · ${s.new_24h} new in the last 24 hours` },
        { label: 'Reach', value: s.reached, title: 'monitored organisations reached',
          sub: `${s.by_link.DIRECT || 0} named victims · ${s.by_link.EXPOSED_PRODUCT || 0} run an exploited product · ${s.by_link.DEPENDENCY || 0} through a provider` },
        { label: 'Most common', value: kinds[0]?.[1] ?? 0, title: kinds[0]?.[0] || '—', sub: 'incident type · click to show only these', onClick: kinds[0] ? () => onKind(kinds[0][0]) : undefined },
        { label: 'Widest reach', value: top?.impacted || 0, title: 'organisation links from one incident', sub: top?.title || '—', onClick: top ? () => onOpen(top.id) : undefined },
      ]} />
      <div className="grid g-main-side">
        <Card title="What happened × how it reaches organisations" sub="distinct monitored organisations per incident type and link rule · darker = more · click a row to show only that type">
          {heat.length ? (
            <div style={{ height: h }}>
              <ResponsiveHeatMap data={heat} margin={{ top: 36, right: 10, bottom: 6, left: 230 }} axisTop={{ tickSize: 0, tickPadding: 8 }} axisLeft={{ tickSize: 0, tickPadding: 8 }}
                colors={((c: any) => (c.value ? heatColor(c.value) : CT.EMPTY)) as any} emptyColor={CT.EMPTY} borderWidth={2} borderColor={CT.SURFACE} enableLabels
                labelTextColor={((c: any) => (c.value ? CT.onFill(heatColor(c.value)) : 'transparent')) as any} theme={CT.nivoTheme as any} hoverTarget="cell" animate
                onClick={(c: any) => onKind(c.serieId)}
                tooltip={({ cell: c }: any) => <div className="tip"><strong>{c.value}</strong> organisation{c.value === 1 ? '' : 's'} · {c.serieId}<div>{c.data.x}</div></div>} />
            </div>) : <Empty>No incident in view reaches a monitored organisation.</Empty>}
        </Card>
        <Card title="New incidents per day" sub={`first seen · by level · last ${range} days`}>
          {s.daily.length ? (
            <>
              <StackedBars data={s.daily.map((d: any) => ({ ...d, label: new Date(`${d.day}T00:00:00`).toLocaleDateString(undefined, { day: 'numeric', month: 'short' }) }))}
                x="label" keys={['critical', 'high', 'medium', 'low']} names={['Critical', 'High', 'Medium', 'Low']}
                colors={[CT.SEV_COLOR.critical, CT.SEV_COLOR.high, CT.SEV_COLOR.medium, CT.SEV_COLOR.low]} height={h - 34} />
              <div className="row wrap" style={{ gap: 10, fontSize: 12 }}>{(['critical', 'high', 'medium', 'low'] as const).map(l => <Sev key={l} level={l} />)}</div>
            </>) : <Empty>No new incidents in this window.</Empty>}
        </Card>
      </div>
    </>
  )
}

export default function Incidents() {
  const { id } = useParams()
  const [sp, setSp] = useSearchParams()
  const nav = useNavigate()
  const { range } = useRange()
  const [tab, setTab] = useState<'incidents' | 'providers'>(sp.get('view') === 'providers' ? 'providers' : 'incidents')
  const [sev, setSev] = useState<string>(sp.get('severity') || '')
  const [q, setQ] = useState('')
  const kind = sp.get('kind') || ''
  const provider = sp.get('provider') || ''
  const { data } = useApi<any>(`/incidents${qs({ days: range, severity: sev, kind, provider, q: q.length > 1 ? q : '' })}`, 60)
  const list = data?.incidents || []
  const selected = id || (list[0]?.id as string | undefined)
  const kinds = useMemo(() => Object.keys(data?.kinds || {}), [data])

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">Incidents & impact</div>
          <h2>From an incident to every organisation it could reach</h2>
          <p>Each incident is clustered from leak sites, filings, dark-web reporting, news, status pages and exploitation data. Organisations are linked by six explainable rules: named victim, corporate group, provider dependency (public DNS), named as an affected customer, exposed product, and sector targeting.</p>
        </div>
      </div>
      <Tabs tabs={[{ id: 'incidents', label: <><Network size={14} />Incidents</>, count: list.length }, { id: 'providers', label: <><Boxes size={14} />Provider concentration</> }]} value={tab} onChange={setTab} />
      {tab === 'providers' ? <Providers /> : (
        <>
          {data && <IncidentSummary data={data} range={range} onOpen={iid => nav(`/incidents/${iid}`)}
            onKind={k => { const n = new URLSearchParams(sp); n.set('kind', k); setSp(n) }} />}
          <SectionLabel>Every incident · select one for its reach, spread and sources</SectionLabel>
          <div className="filters">
            <Seg options={[{ id: '', label: 'All' }, { id: 'critical', label: 'Critical' }, { id: 'high', label: 'High' }, { id: 'medium', label: 'Medium' }, { id: 'low', label: 'Low' }]} value={sev as any} onChange={setSev as any} />
            <select className="txt" value={kind} onChange={e => { const n = new URLSearchParams(sp); e.target.value ? n.set('kind', e.target.value) : n.delete('kind'); setSp(n) }}>
              <option value="">All incident types</option>{kinds.map(k => <option key={k}>{k}</option>)}
            </select>
            <div className="search" style={{ maxWidth: 280 }}><Search size={14} /><input value={q} onChange={e => setQ(e.target.value)} placeholder="victim, actor, vendor, CVE…" /></div>
            {provider && <span className="pill btn on" onClick={() => { const n = new URLSearchParams(sp); n.delete('provider'); setSp(n) }}>Provider: {provider} ✕</span>}
            {data && <SevCounts counts={data.severity || {}} />}
          </div>
          <div className="grid g-side-main" style={{ alignItems: 'start' }}>
            <Card className="flush">
              <div style={{ maxHeight: 'calc(100vh - 290px)', overflowY: 'auto', padding: '4px 12px' }}>
                {!list.length && <Empty>No incidents match.</Empty>}
                <AnimatePresence initial={false}>
                  {list.map((i: any) => (
                    <motion.div key={i.id} layout initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                      className="feed-item clickable" onClick={() => nav(`/incidents/${i.id}${sp.toString() ? '?' + sp.toString() : ''}`)}
                      style={{ gridTemplateColumns: 'auto 1fr', background: i.id === selected ? 'var(--accent-wash)' : undefined, borderRadius: 8, padding: '10px 8px' }}>
                      <Sev level={i.severity} rule={i.severity_rule} compact />
                      <div>
                        <div className="t clamp2">{i.title}</div>
                        <div className="m"><span>{i.kind}</span><When ts={i.last_seen} /><span>{i.source_count} src</span></div>
                        <div style={{ marginTop: 4 }}><ImpactChips impacts={i.impacts} types={data.link_types} /></div>
                      </div>
                    </motion.div>
                  ))}
                </AnimatePresence>
              </div>
            </Card>
            {selected ? <Detail id={selected} /> : <Empty>Select an incident.</Empty>}
          </div>
        </>
      )}
      <PageSources cats={['Dark web', 'News', 'Government', 'Registry', 'Service status', 'Vulnerabilities', 'Research', 'Threat intel']}
        note="Incidents are clustered from these records; each incident's own source trail is listed on its detail panel." />
    </div>
  )
}
