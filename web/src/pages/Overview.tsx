import { useNavigate } from 'react-router-dom'
import { motion } from 'motion/react'
import { ArrowRight } from 'lucide-react'
import { useApi } from '../lib/api'
import { useRange } from '../App'
import { Card, Stat, Sev, Empty, When, SourceLink } from '../components/ui'
import WorldMap from '../components/WorldMap'
import { StackedArea, HBar } from '../components/charts'
import { SEV_COLOR } from '../lib/chartTheme'
import { compact } from '../lib/format'

const LT_SHORT: Record<string, string> = { DIRECT: 'victim', GROUP: 'group', DEPENDENCY: 'uses provider', EXPOSED_PRODUCT: 'exposed product', TARGETING: 'sector targeted' }

export default function Overview() {
  const { range } = useRange()
  const nav = useNavigate()
  const { data, isFetching } = useApi<any>(`/overview?days=${range}`, 60)
  if (!data) return <div className="muted">Assembling the live picture…</div>
  const h = data.hero
  const keys = ['Leak-site listings', 'Dark-web claims', 'DDoS targets', 'KEV additions'].filter(k => data.series.some((s: any) => s[k]))
  return (
    <div style={{ opacity: isFetching ? 0.85 : 1, transition: 'opacity .3s' }}>
      <div className="page-head">
        <div>
          <div className="eyebrow">Situation · last {range} days</div>
          <h2>Cyber risk across {compact(h.monitored)} monitored organisations</h2>
          <p>Live incidents, who they could reach, and what changed — every figure links to its evidence. Levels are assigned by named rules, not scores.</p>
        </div>
      </div>

      {data.incidents?.length > 0 && (
        <div className="card flush" style={{ overflow: 'hidden', marginBottom: 14, padding: '9px 0' }}>
          <div className="ticker">
            {[...data.incidents, ...data.incidents].map((i: any, k: number) => (
              <span key={k} className="row" style={{ cursor: 'pointer' }} onClick={() => nav(`/incidents/${i.id}`)}>
                <Sev level={i.severity} compact /> <span className="ink2">{i.title}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="grid" style={{ gridTemplateColumns: '1.3fr repeat(3, 1fr)', marginBottom: 14 }}>
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}>
          <Stat hero label="Organisations with a Critical finding" value={<span>{h.critical_orgs}<span className="muted" style={{ fontSize: 20, fontWeight: 500 }}> / {h.monitored}</span></span>}
            hint="Leak-site listing, 8-K incident, exposed exploited CVE, C2 in owned space…" onClick={() => nav('/orgs?level=critical')} />
        </motion.div>
        <Stat label="Active incidents" value={h.incidents} hint={<><span style={{ color: SEV_COLOR.critical }}>●</span> {h.incidents_critical} critical</>} onClick={() => nav('/incidents')} />
        <Stat label="Organisations linked to an incident" value={h.orgs_impacted} hint="victim · group · provider · exposed product" onClick={() => nav('/incidents')} />
        <Stat label="New Critical/High findings (24h)" value={h.new_findings_24h} hint="since yesterday" onClick={() => nav('/orgs')} />
      </div>
      <div className="grid g4" style={{ marginBottom: 14 }}>
        <Stat label="Leak-site listings" value={compact(h.leak_listings)} hint="ransomware & extortion sites" onClick={() => nav('/darkweb')} />
        <Stat label="Dark-web claims" value={compact(h.forum_claims)} hint="access, data & credential sales (reported)" onClick={() => nav('/darkweb')} />
        <Stat label="Newly exploited CVEs" value={compact(h.kev_added)} hint="added to CISA KEV" onClick={() => nav('/exposure')} />
        <Stat label="Incident types" value={Object.keys(data.kinds || {}).length} hint={Object.entries(data.kinds || {}).sort((a: any, b: any) => b[1] - a[1]).slice(0, 2).map(([k]) => k).join(' · ')} />
      </div>

      <div className="grid g-main-side" style={{ marginBottom: 14, alignItems: 'start' }}>
        <div className="stack" style={{ gap: 14 }}>
          <Card title="Where incidents are landing" sub="victim HQ (or country) · pulsing = critical in the last 72h · click to open">
            <WorldMap height={400} points={data.points.map((p: any) => ({ ...p, onClick: () => nav(`/incidents/${p.id}`) }))} />
            <div className="legend" style={{ marginTop: 10 }}>
              {['critical', 'high', 'medium', 'low'].map(l => <span key={l}><Sev level={l} /> {data.severity?.[l] || 0}</span>)}
            </div>
          </Card>
          <Card title="Threat activity" sub="daily counts from leak sites, dark-web reporting, DDoSia target lists and CISA KEV">
            {data.series.length ? <StackedArea data={data.series} keys={keys} height={250} /> : <Empty>Waiting for first collection cycle.</Empty>}
          </Card>
        </div>
        <div className="stack" style={{ gap: 14 }}>
        <Card title="Priority incidents" sub="ranked by level, then reach" right={<a className="srclink" onClick={() => nav('/incidents')}>All <ArrowRight size={12} /></a>}>
          <div className="feed" style={{ maxHeight: 560, overflowY: 'auto' }}>
            {data.incidents.length === 0 && <Empty>No incidents in this window yet — collectors are still running.</Empty>}
            {data.incidents.map((i: any) => (
              <div key={i.id} className="feed-item clickable" style={{ gridTemplateColumns: 'auto 1fr' }} onClick={() => nav(`/incidents/${i.id}`)}>
                <Sev level={i.severity} rule={i.severity_rule} compact />
                <div>
                  <div className="t clamp2">{i.title}</div>
                  <div className="m">
                    <span>{i.kind}</span><When ts={i.last_seen} /><span>{i.source_count} source{i.source_count === 1 ? '' : 's'}</span>
                    {Object.entries(i.impacts || {}).filter(([k]) => k !== 'TARGETING').map(([k, n]) => <span key={k} className="pill">{n as number} {LT_SHORT[k]}</span>)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
        <Card title="What changed" sub="newest Critical / High findings">
          <div className="feed" style={{ maxHeight: 420, overflowY: 'auto' }}>
            {data.changed.length === 0 && <Empty>No Critical or High findings yet.</Empty>}
            {data.changed.map((f: any) => (
              <div key={f.id} className="feed-item clickable" style={{ gridTemplateColumns: 'auto 1fr' }} onClick={() => nav(`/orgs/${f.org_id}`)}>
                <Sev level={f.severity} rule={f.rule_id} compact />
                <div>
                  <div className="t trunc">{f.org}</div>
                  <div className="m"><span className="clamp2">{f.title}</span></div>
                  <div className="m"><When ts={f.first_seen} /><span className="mono">{f.rule_id}</span>{f.evidence_url?.startsWith('http') && <SourceLink url={f.evidence_url} />}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
        </div>
      </div>

      <div className="grid g3">
        <Card title="Most active extortion groups" sub="leak-site victims in window · click for profile">
          {data.groups.length ? <HBar data={data.groups} label="group" value="n" onClick={d => nav(`/adversaries/rw-${String(d.group).toLowerCase()}`)} /> : <Empty>No listings yet.</Empty>}
        </Card>
        <Card title="Themes in the reporting" sub="last 14 days · click to analyse">
          {data.themes.length ? <HBar data={data.themes} label="theme" value="n" onClick={d => nav(`/analyst?theme=${encodeURIComponent(d.theme)}`)} /> : <Empty>No reporting yet.</Empty>}
        </Card>
        <Card title="Incident mix" sub="by type">
          {Object.keys(data.kinds || {}).length ? <HBar data={Object.entries(data.kinds).map(([k, n]) => ({ kind: k, n })).sort((a: any, b: any) => b.n - a.n)} label="kind" value="n"
            onClick={d => nav(`/incidents?kind=${encodeURIComponent(d.kind)}`)} /> : <Empty>No incidents yet.</Empty>}
        </Card>
      </div>
    </div>
  )
}
