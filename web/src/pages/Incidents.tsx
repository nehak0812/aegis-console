import { useMemo, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { ResponsiveNetwork } from '@nivo/network'
import { ResponsiveTreeMap } from '@nivo/treemap'
import { motion, AnimatePresence } from 'motion/react'
import { Network, Boxes, Search } from 'lucide-react'
import { useApi, qs } from '../lib/api'
import { useRange } from '../App'
import { Card, Sev, Why, Empty, When, SourceLink, Tabs, Seg, Table, SevCounts } from '../components/ui'
import { HBar } from '../components/charts'
import { nivoTheme, SEV_COLOR, SERIES, NEUTRAL, SURFACE, INK, onFill } from '../lib/chartTheme'
import { day, pct } from '../lib/format'

// resolved on read so the active theme's palette applies
const LT_COLOR: Record<string, string> = new Proxy({} as Record<string, string>, {
  get: (_t, k: string) => ({ DIRECT: SERIES[7], GROUP: SERIES[6], DEPENDENCY: SERIES[0], EXPOSED_PRODUCT: SERIES[1], TARGETING: NEUTRAL } as Record<string, string>)[k],
})
const LT_ORDER = ['DIRECT', 'GROUP', 'EXPOSED_PRODUCT', 'DEPENDENCY', 'TARGETING']

function ImpactChips({ impacts, types }: { impacts: Record<string, number>; types: Record<string, string> }) {
  return (
    <span className="row wrap" style={{ gap: 4 }}>
      {LT_ORDER.filter(k => impacts?.[k]).map(k => (
        <span key={k} className="pill" title={types[k]}><span className="dot" style={{ background: LT_COLOR[k] }} />{impacts[k]} {k === 'EXPOSED_PRODUCT' ? 'exposed' : k.toLowerCase()}</span>
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
          <Empty>No monitored organisation is linked to this incident by the five linkage rules (victim, corporate group, provider dependency, exposed product, sector targeting). The victim may be outside the monitored universe.</Empty>
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

function Providers() {
  const nav = useNavigate()
  const { data } = useApi<any>('/linkage/providers', 300)
  if (!data) return <div className="muted">Loading…</div>
  const tree = { id: 'providers', children: Object.entries(
    data.providers.reduce((acc: any, p: any) => { (acc[p.category] ||= []).push(p); return acc }, {})
  ).map(([cat, ps]: any) => ({ id: cat, children: ps.slice(0, 14).map((p: any) => ({ id: p.vendor, value: p.n, hot: p.incidents.length > 0, cat })) })) }
  return (
    <div className="grid g-main-side">
      <Card title="Provider concentration" sub={`shared third parties across ${data.scanned_orgs} scanned organisations (from public DNS) · red outline = active incident`}>
        <div style={{ height: 520 }}>
          <ResponsiveTreeMap data={tree as any} identity="id" value="value" leavesOnly innerPadding={2} outerPadding={2}
            label={(n: any) => `${n.id} · ${n.value}`} labelSkipSize={36}
            colors={(n: any) => SERIES[Object.keys(data.categories).indexOf(n.data.cat) % SERIES.length]}
            nodeOpacity={0.85} borderWidth={3} borderColor={((n: any) => (n.data?.hot ? SEV_COLOR.critical : SURFACE)) as any}
            labelTextColor={((n: any) => onFill(n.color)) as any} parentLabelTextColor={INK} theme={nivoTheme as any} animate motionConfig="gentle"
            onClick={(n: any) => nav(`/incidents?provider=${encodeURIComponent(n.id)}`)}
            tooltip={({ node }: any) => <div className="tip"><strong>{node.id}</strong><div>{node.value} monitored organisations · {node.data.cat}</div>{node.data.hot && <div style={{ color: SEV_COLOR.critical }}>Active incident</div>}</div>} />
        </div>
      </Card>
      <Card title="If one of these is hit…" sub="providers with the widest reach">
        <Table rows={data.providers.slice(0, 25)} onRow={(p: any) => nav(`/incidents?provider=${encodeURIComponent(p.vendor)}`)}
          cols={[
            { key: 'vendor', label: 'Provider', render: (p: any) => <><b>{p.vendor}</b><div className="muted" style={{ fontSize: 12 }}>{p.category}</div></> },
            { key: 'n', label: 'Orgs', num: true },
            { key: 'share', label: 'Share', num: true, render: (p: any) => pct(p.share, 0) },
            { key: 'inc', label: 'Active', render: (p: any) => p.incidents.length ? <Sev level={p.incidents[0].severity} compact /> : <span className="muted">—</span>, sort: (p: any) => p.incidents.length },
          ]} />
      </Card>
    </div>
  )
}

export default function Incidents() {
  const { id } = useParams()
  const [sp, setSp] = useSearchParams()
  const nav = useNavigate()
  const { range } = useRange()
  const [tab, setTab] = useState<'incidents' | 'providers'>('incidents')
  const [sev, setSev] = useState<string>(sp.get('severity') || '')
  const [q, setQ] = useState('')
  const kind = sp.get('kind') || ''
  const provider = sp.get('provider') || ''
  const { data } = useApi<any>(`/incidents${qs({ days: Math.max(Number(range), 30), severity: sev, kind, provider, q: q.length > 1 ? q : '' })}`, 60)
  const list = data?.incidents || []
  const selected = id || (list[0]?.id as string | undefined)
  const kinds = useMemo(() => Object.keys(data?.kinds || {}), [data])

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">Incidents & impact</div>
          <h2>From an incident to every organisation it could reach</h2>
          <p>Each incident is clustered from leak sites, filings, dark-web reporting, news and exploitation data. Organisations are linked by five explainable rules: named victim, corporate group, provider dependency (public DNS), exposed product, and sector targeting.</p>
        </div>
      </div>
      <Tabs tabs={[{ id: 'incidents', label: <><Network size={14} />Incidents</>, count: list.length }, { id: 'providers', label: <><Boxes size={14} />Provider concentration</> }]} value={tab} onChange={setTab} />
      {tab === 'providers' ? <Providers /> : (
        <>
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
    </div>
  )
}
