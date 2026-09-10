import { useMemo, useState } from 'react'
import { ResponsiveSunburst } from '@nivo/sunburst'
import { useApi } from '../lib/api'
import { Card, Stat, Empty, SourceLink, When, Legend } from '../components/ui'
import { HBar, Columns } from '../components/charts'
import { SERIES, nivoTheme, SURFACE, onFill } from '../lib/chartTheme'

export default function AIRisk() {
  const { data } = useApi<any>('/ai', 600)
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
          <h2>AI risk through the MIT AI Risk Repository lens</h2>
          <p>The MIT Domain Taxonomy (7 domains, 24 subdomains) with live counts of catalogued risks, and new AI incident reports classified into it by transparent keyword rules. Cyber-relevant subdomains (2.1, 2.2, 4.1–4.3, 7.3) feed the SOC view.</p>
        </div>
        <div style={{ marginLeft: 'auto' }}><SourceLink url="https://airisk.mit.edu/" label="MIT AI Risk Repository" /></div>
      </div>
      <div className="grid g4" style={{ marginBottom: 14 }}>
        <Stat label="Risks catalogued by MIT" value={(mit?.total_risks || 0).toLocaleString()} hint="from 70+ frameworks" />
        <Stat label="AI incident reports" value={data.incidents.length} hint="AI Incident Database, newest" />
        <Stat label="Cyber-relevant incidents" value={data.incidents.filter((i: any) => ['2.1', '2.2', '4.1', '4.2', '4.3', '7.3'].includes(i.entities?.mit)).length} hint="privacy, security, misuse, robustness" />
        <Stat label="AI-security reporting (60d)" value={data.cyber_ai_reporting.length} hint="news & research on AI attacks / AI security" />
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
    </div>
  )
}
