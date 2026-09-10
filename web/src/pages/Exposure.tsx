import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { ResponsiveHeatMap } from '@nivo/heatmap'
import { useApi } from '../lib/api'
import { Gloss } from '../lib/glossary'
import { useRange } from '../App'
import { Card, Stat, Sev, Table, Empty, SourceLink, Tabs, Legend } from '../components/ui'
import { HBar, Columns } from '../components/charts'
import { SEV_COLOR, nivoTheme, SERIES, EMPTY, SURFACE } from '../lib/chartTheme'
import { pct, compact, day } from '../lib/format'

const RANKV: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }
const VLBL = ['none', 'Low', 'Medium', 'High', 'Critical']

function CveCard({ cve }: { cve: string }) {
  const { data } = useApi<any>(`/vulns/${cve}`, 600)
  const nav = useNavigate()
  if (!data) return null
  return (
    <Card title={cve} sub={`${data.vendor || ''} ${data.product || ''}`} right={<SourceLink url={`https://nvd.nist.gov/vuln/detail/${cve}`} label="NVD" />}>
      <div className="row wrap" style={{ gap: 8, marginBottom: 8 }}><Sev level={data.severity} rule={data.severity_rule} /><span className="pill">EPSS {pct(data.epss)}</span>{data.kev_added && <span className="pill">KEV since {data.kev_added}</span>}{data.cvss && <span className="pill">CVSS {data.cvss}</span>}</div>
      <div className="ink2" style={{ marginBottom: 8 }}>{data.description}</div>
      <div className="muted" style={{ fontSize: 12 }}>Monitored organisations with this CVE on an indexed host:</div>
      <div className="row wrap" style={{ gap: 6, marginTop: 6 }}>{data.exposed.length ? data.exposed.map((e: any) => <span key={e.ip} className="pill btn" onClick={() => nav(`/orgs/${e.org_id}`)}>{e.org_id} · {e.ip}</span>) : <span className="muted">none</span>}</div>
    </Card>
  )
}

export default function Exposure() {
  const { range } = useRange()
  const nav = useNavigate()
  const [sp] = useSearchParams()
  const [tab, setTab] = useState<'exploited' | 'watchlist' | 'compromised'>('exploited')
  const [vendor, setVendor] = useState('')
  const { data } = useApi<any>(`/exposure?days=${range}`, 300)
  const VCOL = [EMPTY, SEV_COLOR.low, SEV_COLOR.medium, SEV_COLOR.high, SEV_COLOR.critical]
  if (!data) return <div className="muted">Loading exposure…</div>
  const cve = sp.get('cve')
  const recent = vendor ? data.kev_recent.filter((v: any) => (v.vendor || '').trim() === vendor) : data.kev_recent
  const heat = data.matrix.orgs.map((o: any) => ({ id: o.name, oid: o.id, data: data.matrix.categories.map(([k, l]: any) => ({ x: l, y: RANKV[o.cells[k]] || 0 })) }))

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">Exposure & vulnerabilities</div>
          <h2>Exploited software, exposed services and compromised hosts</h2>
          <p><Gloss>CISA KEV, FIRST EPSS, public exploit availability and CVE records set each vulnerability's level by rule. Exposure across the monitored organisations comes from passive indexes only.</Gloss></p>
        </div>
      </div>
      {cve && <div style={{ marginBottom: 14 }}><CveCard cve={cve} /></div>}
      <div className="grid g4" style={{ marginBottom: 14 }}>
        <Stat label="Actively exploited CVEs (KEV)" value={compact(data.kev_total)} hint={`${data.severity.critical || 0} Critical by rule`} />
        <Stat label={`Added in the last ${range} days`} value={data.kev_recent.length} hint="fresh exploitation" />
        <Stat label="Used in ransomware" value={data.ransomware_linked} hint="CISA 'known ransomware use'" />
        <Stat label="Organisations surface-scanned" value={data.scanned_orgs} hint="rolling passive scan" />
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[{ id: 'exploited', label: 'Exploited software' }, { id: 'watchlist', label: 'Across the watchlist' }, { id: 'compromised', label: 'Compromised IPs' }]} />

      {tab === 'exploited' && (
        <div className="stack" style={{ gap: 14 }}>
          <div className="grid g-main-side">
            <Card title="New exploited vulnerabilities per week" sub="CISA KEV additions, last 12 months">
              <Columns data={data.kev_weekly} x="week" y="n" height={230} fmtX={(s: string) => new Date(s).toLocaleDateString(undefined, { day: 'numeric', month: 'short' })} />
            </Card>
            <Card title="Most-exploited vendors" sub="KEV additions, 12 months · click to filter">
              <HBar data={data.kev_vendors} label="vendor" value="n" onClick={d => setVendor(vendor === d.vendor ? '' : d.vendor)} colorFn={d => (d.vendor === vendor ? SERIES[1] : SERIES[0])} />
            </Card>
          </div>
          <Card title={`Recently exploited${vendor ? ` — ${vendor}` : ''}`} sub="level assigned by rule; hover the level for the reason">
            <Table rows={recent} empty="No KEV additions in this window." cols={[
              { key: 'cve', label: 'CVE', render: (v: any) => <SourceLink url={`https://nvd.nist.gov/vuln/detail/${v.cve}`} label={v.cve} /> },
              { key: 'severity', label: 'Level', render: (v: any) => <Sev level={v.severity} rule={v.severity_rule} />, sort: (v: any) => RANKV[v.severity] },
              { key: 'vendor', label: 'Product', render: (v: any) => <><b>{v.vendor}</b> {v.product}<div className="muted" style={{ fontSize: 12 }}>{v.name}</div></> },
              { key: 'kev_added', label: 'Added', render: (v: any) => day(v.kev_added) },
              { key: 'epss', label: 'EPSS', num: true, render: (v: any) => pct(v.epss) },
              { key: 'ransomware', label: 'Ransomware', render: (v: any) => v.ransomware === 'Known' ? <span className="pill">Known</span> : '' },
              { key: 'exploit_refs', label: 'Public exploit', render: (v: any) => (v.exploit_refs || []).slice(0, 2).map((r: any) => <div key={r.url}><SourceLink url={r.url} label={r.src} /></div>), sort: (v: any) => (v.exploit_refs || []).length },
            ]} />
          </Card>
          <Card title="Highest exploit probability" sub="FIRST EPSS — probability of exploitation in the next 30 days">
            <Table rows={data.top_epss} max={60} cols={[
              { key: 'cve', label: 'CVE', render: (v: any) => <SourceLink url={`https://nvd.nist.gov/vuln/detail/${v.cve}`} label={v.cve} /> },
              { key: 'severity', label: 'Level', render: (v: any) => <Sev level={v.severity} rule={v.severity_rule} /> },
              { key: 'vendor', label: 'Product', render: (v: any) => `${v.vendor || ''} ${v.product || ''}` },
              { key: 'epss', label: 'EPSS', num: true, render: (v: any) => pct(v.epss) }, { key: 'kev_added', label: 'In KEV', render: (v: any) => v.kev_added ? 'yes' : '' }]} />
          </Card>
        </div>
      )}

      {tab === 'watchlist' && (
        <div className="stack" style={{ gap: 14 }}>
          <Card title="Exposure matrix" sub="most exposed organisations × assessment category · cell = worst level · click a row to open">
            {heat.length ? (
              <>
                <div style={{ height: Math.max(260, heat.length * 26 + 110) }}>
                  <ResponsiveHeatMap data={heat} margin={{ top: 100, right: 10, bottom: 10, left: 190 }} valueFormat={(v: number) => VLBL[v]}
                    axisTop={{ tickRotation: -38, tickSize: 0, tickPadding: 6 }} axisLeft={{ tickSize: 0, tickPadding: 8 }}
                    colors={((cell: any) => VCOL[cell.value || 0]) as any} emptyColor={EMPTY} borderWidth={2} borderColor={SURFACE}
                    enableLabels={false} theme={nivoTheme as any} hoverTarget="cell" animate
                    onClick={(cell: any) => { const r = heat.find((h: any) => h.id === cell.serieId); if (r) nav(`/orgs/${r.oid}`) }}
                    tooltip={({ cell }: any) => <div className="tip"><strong>{cell.serieId}</strong><div>{cell.data.x}: {VLBL[cell.value || 0]}</div></div>} />
                </div>
                <Legend items={[4, 3, 2, 1].map(v => ({ label: VLBL[v], color: VCOL[v] }))} />
              </>) : <Empty>Findings appear once the first scans complete.</Empty>}
          </Card>
          <div className="grid g3">
            <Card title="Open ports on owned hosts" sub="risk-relevant services flagged">
              {data.ports.length ? <HBar data={data.ports.map((p: any) => ({ ...p, label: `${p.port}${p.service ? ' · ' + p.service : ''}` }))} label="label" value="n" colorFn={p => (p.risky ? SEV_COLOR.high : SERIES[0])} /> : <Empty>Awaiting scans.</Empty>}
              <Legend items={[{ label: 'Remote-admin / database port', color: SEV_COLOR.high }, { label: 'Other', color: SERIES[0] }]} />
            </Card>
            <Card title="Edge & remote-access products" sub="organisations whose public hostnames indicate the product">
              {data.edge_products.length ? <HBar data={data.edge_products} label="product" value="orgs" /> : <Empty>Awaiting scans.</Empty>}
            </Card>
            <Card title="Cloud environments" sub="public IPs attributed to providers">
              {data.cloud.length ? <HBar data={data.cloud} label="provider" value="ips" /> : <Empty>Awaiting scans.</Empty>}
            </Card>
          </div>
          <Card title="Exposure findings across the watchlist">
            <Table rows={data.exposed_findings} onRow={(f: any) => nav(`/orgs/${f.org_id}`)} empty="No exposure findings yet." cols={[
              { key: 'severity', label: 'Level', render: (f: any) => <Sev level={f.severity} rule={f.rule_id} />, sort: (f: any) => RANKV[f.severity] },
              { key: 'org', label: 'Organisation' }, { key: 'title', label: 'Finding' },
              { key: 'evidence_url', label: '', render: (f: any) => f.evidence_url?.startsWith('http') ? <SourceLink url={f.evidence_url} /> : null }]} />
          </Card>
        </div>
      )}

      {tab === 'compromised' && (
        <div className="grid g2">
          <Card title="Compromised-host & attacker feeds" sub="refreshed every 6 hours; intersected with owned IP space only">
            <Table rows={Object.values(data.blocklists)} cols={[
              { key: 'name', label: 'Feed', render: (f: any) => <SourceLink url={f.url} label={f.name} /> }, { key: 'entries', label: 'Entries', num: true },
              { key: 'category', label: 'Category' }, { key: 'licence', label: 'Licence' }, { key: 'ok', label: '', render: (f: any) => f.ok ? '' : <Sev level="medium" /> }]} />
          </Card>
          <Card title="Listings inside monitored organisations' networks">
            {data.compromised.length ? <Table rows={data.compromised} onRow={(m: any) => nav(`/orgs/${m.org_id}`)} cols={[
              { key: 'org_id', label: 'Organisation' }, { key: 'listed', label: 'Address', render: (m: any) => <span className="mono">{m.listed}</span> },
              { key: 'feed_name', label: 'Feed' }, { key: 'provenance', label: 'Why attributed' }]} />
              : <Empty>No listed address falls inside any monitored organisation's owned or declared IP space. Only owned ranges are checked, so absence of a listing is not proof of absence of compromise.</Empty>}
          </Card>
        </div>
      )}
    </div>
  )
}
