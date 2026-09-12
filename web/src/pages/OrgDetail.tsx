import { useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { motion } from 'motion/react'
import { ResponsiveTreeMap } from '@nivo/treemap'
import { RefreshCw, CheckCircle2, XCircle, MinusCircle, ExternalLink } from 'lucide-react'
import { useApi, api } from '../lib/api'
import { Card, Sev, Why, Empty, When, SourceLink, Tabs, Table, SevCounts, Stat, useRules, ActBy } from '../components/ui'
import { HBar, Columns, StackedArea } from '../components/charts'
import { ActionTable } from '../components/actions'
import { OrgBrief } from '../components/brief'
import { SEV_COLOR, SERIES, nivoTheme, EMPTY, SURFACE, onFill, INK, INK2 } from '../lib/chartTheme'
import { countryName, day, compact } from '../lib/format'

type Tab = 'summary' | 'assets' | 'third' | 'exposure' | 'compromise' | 'events' | 'impersonation' | 'hygiene' | 'findings' | 'prevent'
const CAT_TAB: Record<string, Tab> = { footprint: 'assets', critical: 'assets', cloud: 'assets', software: 'third', exposure: 'exposure', vulns: 'exposure',
  compromise: 'compromise', darkweb: 'events', chatter: 'events', hygiene: 'hygiene', disclosure: 'events', ai: 'events', impersonation: 'impersonation' }
const LT: Record<string, string> = { DIRECT: 'Named victim', GROUP: 'Corporate group', DEPENDENCY: 'Provider dependency', EXPOSED_PRODUCT: 'Exposed product', NAMED_CUSTOMER: 'Named customer', TARGETING: 'Sector targeting' }

function Check({ ok, warn, label, detail, url }: { ok: boolean; warn?: boolean; label: string; detail?: string; url?: string }) {
  const Icon = ok ? CheckCircle2 : warn ? MinusCircle : XCircle
  const color = ok ? 'var(--good)' : warn ? 'var(--medium)' : 'var(--high)'
  return (
    <div className="feed-item" style={{ gridTemplateColumns: 'auto 1fr auto' }}>
      <Icon size={16} color={color} />
      <div><div className="t">{label} <span className="muted" style={{ fontWeight: 400 }}>· {ok ? 'present' : warn ? 'partial' : 'missing'}</span></div>{detail && <div className="m mono" style={{ wordBreak: 'break-all' }}>{detail}</div>}</div>
      {url ? <SourceLink url={url} label="DNS record" /> : <span />}
    </div>
  )
}

function FindingList({ rows, empty }: { rows: any[]; empty?: string }) {
  if (!rows.length) return <Empty>{empty || 'No findings in this category.'}</Empty>
  return (
    <div className="feed">
      {rows.map(f => (
        <div key={f.id} className="feed-item" style={{ gridTemplateColumns: 'auto 1fr auto' }}>
          <Sev level={f.severity} rule={f.rule_id} />
          <div>
            <div className="t">{f.title}</div>
            {f.detail && <div className="m">{f.detail}</div>}
            <div style={{ marginTop: 6 }}><Why rule={f.rule_id} level={f.severity} /></div>
            <div className="m" style={{ marginTop: 4 }}><ActBy ts={f.act_by} rule={f.deadline_rule} />
              {f.data?.exploited_since && <span title="CISA KEV addition date of the CVE involved">exploited since {day(f.data.exploited_since)}{f.data.fastest_lag != null ? ` (${f.data.fastest_lag <= 0 ? 'zero-day' : f.data.fastest_lag + 'd after disclosure'})` : ''}</span>}
              <span>observed {day(f.observed)}</span><span>first seen <When ts={f.first_seen} /></span><span className="mono">{f.source_id}</span></div>
          </div>
          {f.evidence_url?.startsWith('http') ? <SourceLink url={f.evidence_url} /> : f.evidence_url?.startsWith('/') ? <a className="srclink" href={f.evidence_url}>Open</a> : <span />}
        </div>
      ))}
    </div>
  )
}

export default function OrgDetail() {
  const { id } = useParams()
  const nav = useNavigate()
  const { data, refetch } = useApi<any>(`/orgs/${id}`, 90)
  const [tab, setTab] = useState<Tab>((new URLSearchParams(window.location.search).get('tab') as Tab) || 'summary')  // deep link: ?tab=impersonation
  const [cat, setCat] = useState<string | null>(null)
  const [queued, setQueued] = useState(false)
  useRules()
  const byCat = useMemo(() => {
    const m: Record<string, any[]> = {}
    for (const f of data?.findings || []) (m[f.category] ||= []).push(f)
    return m
  }, [data])
  if (!data) return <div className="muted">Loading organisation…</div>
  const o = data.org, p = data.posture, fp = data.footprint
  const scanned = !!fp.scanned
  const catFindings = (cats: string[]) => (data.findings as any[]).filter(f => cats.includes(f.category))
  const depCats = Object.keys(data.dependencies)
  const catColor = (c: string) => SERIES[Math.max(0, depCats.indexOf(c)) % SERIES.length] || EMPTY
  const tpTree = { id: 'deps', children: Object.entries(data.dependencies).map(([c, vs]: any) => ({ id: c, children: vs.map((v: any) => ({ id: `${v.vendor}`, value: 1, n: v.evidence.length, cat: c, issue: data.provider_issues?.[v.vendor] })) })) }  // one equal tile per provider, so every label fits; record counts are in the tooltip and evidence panel
  const hy = fp.domain?.attrs?.hygiene || {}
  const d = fp.domain?.value || o.domain
  const dohUrl = (n: string, t: string) => `https://dns.google/resolve?name=${n}&type=${t}`
  const stealer = data.leaks.find((l: any) => l.kind === 'stealer')

  const rescan = async () => { await api(`/orgs/${id}/scan`, { method: 'POST' }); setQueued(true); setTimeout(() => refetch(), 60000) }

  return (
    <div>
      <Card className="fade-in">
        <div className="row wrap" style={{ gap: 14, alignItems: 'flex-start' }}>
          <div style={{ flex: 1, minWidth: 280 }}>
            <div className="eyebrow">Entity view</div>
            <h2 style={{ margin: '4px 0 6px', fontSize: 24 }}>{o.name} {o.ticker && <span className="muted mono" style={{ fontSize: 14 }}>{o.ticker}</span>}</h2>
            <div className="ink2">{[o.sector, o.industry].filter(Boolean).join(' · ')} — {[o.city, countryName(o.country)].filter(Boolean).join(', ')}</div>
            <div className="row wrap" style={{ gap: 6, marginTop: 10 }}>
              {(o.indices || []).map((i: string) => <span key={i} className="pill">{i}</span>)}
              {o.website && <a className="pill btn" href={o.website} target="_blank" rel="noreferrer">{o.domain} <ExternalLink size={10} /></a>}
              {o.lei && <a className="pill btn" href={`https://search.gleif.org/#/record/${o.lei}`} target="_blank" rel="noreferrer">LEI {o.lei} <ExternalLink size={10} /></a>}
              {o.cik && <a className="pill btn" href={`https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=${o.cik}&type=8-K`} target="_blank" rel="noreferrer">SEC filings <ExternalLink size={10} /></a>}
              {o.wikidata && <a className="pill btn" href={`https://www.wikidata.org/wiki/${o.wikidata}`} target="_blank" rel="noreferrer">Wikidata <ExternalLink size={10} /></a>}
            </div>
          </div>
          <div className="stack" style={{ alignItems: 'flex-end', gap: 8 }}>
            <div className="row" style={{ gap: 10 }}><span className="muted">Current level</span>{p.level ? <span style={{ transform: 'scale(1.25)', transformOrigin: 'right' }}><Sev level={p.level} /></span> : <span className="pill">Not yet assessed</span>}</div>
            <SevCounts counts={p.counts} />
            <div className="row" style={{ gap: 8 }}>
              <span className="muted" style={{ fontSize: 12 }}>Surface scan: {scanned ? <When ts={fp.scanned} /> : 'queued'}</span>
              <button className="btn" onClick={rescan} disabled={queued}><RefreshCw size={13} />{queued ? 'Scan queued' : 'Rescan now'}</button>
            </div>
          </div>
        </div>
      </Card>

      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(190px, 1fr))', margin: '14px 0' }}>
        {data.categories.map(([key, label]: [string, string], i: number) => {
          const lvl = p.by_category?.[key]
          const n = byCat[key]?.length || 0
          return (
            <motion.div key={key} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.03 }}
              className={`cat-tile ${cat === key ? 'on' : ''}`} onClick={() => { setCat(key); setTab(CAT_TAB[key]) }}>
              <span style={{ fontSize: 12.5, fontWeight: 600 }}>{label}</span>
              <span className="row" style={{ justifyContent: 'space-between' }}>
                {lvl ? <Sev level={lvl} /> : <span className="muted" style={{ fontSize: 12 }}>{scanned || !['footprint', 'critical', 'cloud', 'software', 'exposure', 'vulns', 'hygiene', 'compromise'].includes(key) ? (data.inventory?.[key] ? 'No issues' : 'Nothing found') : 'Awaiting scan'}</span>}
                <span className="muted" style={{ fontSize: 12 }}>{n ? `${n} finding${n > 1 ? 's' : ''}` : ''}</span>
              </span>
              <span className="muted" style={{ fontSize: 11.5, minHeight: 14 }}>{data.inventory?.[key] || ''}</span>
              <span style={{ display: 'none' }}>
              </span>
            </motion.div>
          )
        })}
      </div>

      <Tabs value={tab} onChange={t => { setTab(t); setCat(null) }} tabs={[
        { id: 'summary', label: 'Overview' }, { id: 'assets', label: 'Assets & cloud' }, { id: 'third', label: 'Software & third parties' },
        { id: 'exposure', label: 'Exposure & vulnerabilities' }, { id: 'compromise', label: 'Compromised IPs' }, { id: 'events', label: 'Dark web & incidents' },
        { id: 'impersonation', label: 'Impersonation', count: data.impersonation?.total || undefined },
        { id: 'hygiene', label: 'Email & domain' }, { id: 'prevent', label: 'Prevent & actions', count: (data.actions || []).filter((a: any) => a.open).length || undefined },
        { id: 'findings', label: 'All findings', count: data.findings.length }]} />

      {tab === 'impersonation' && (() => {
        const im = data.impersonation || {}
        const SRC = ['Threat-report indicator', 'Newly registered domain', 'Phishing feed', 'Malware / C2 feed']
        return (
          <div className="stack" style={{ gap: 14 }}>
            <div className="grid g4">
              <Stat label="Lookalike domains" value={im.total || 0} hint="from threat reports, new registrations and feeds" />
              <Stat label="Still resolving" value={im.live || 0} hint="public DNS check — block these first" />
              <Stat label="New in the last 30 days" value={im.new_30d || 0} hint="registered or published" />
              <Stat label="PhishTank pages targeting the brand" value={im.phishtank || 0} hint={im.phishtank_url ? <SourceLink url={im.phishtank_url} label="example" /> : 'verified and online'} />
            </div>
            <div className="grid g-main-side">
              <Card title="Impersonation findings" sub="each with the rule and the matching reason">
                <FindingList rows={catFindings(['impersonation'])} empty="No lookalike of this brand in threat reports, new registrations or phishing feeds. The daily new-domain list samples generic TLDs only." />
              </Card>
              <div className="stack" style={{ gap: 14 }}>
                <Card title="Lures used against this brand" sub="what the lookalikes pretend to be">
                  {(im.lures || []).length ? <HBar data={im.lures} label="lure" value="n" /> : <Empty>None.</Empty>}
                </Card>
                <Card title="Where they come from">
                  {(im.sources || []).length ? <HBar data={im.sources} label="source" value="n" colorFn={(d: any) => SERIES[SRC.indexOf(d.source) % SERIES.length]} /> : <Empty>None.</Empty>}
                </Card>
              </div>
            </div>
            {(im.rows || []).length > 0 && (
              <>
                <div className="grid g2">
                  <Card title="Lookalikes over time" sub="12 weeks, by source">
                    <StackedArea data={im.timeline} keys={im.timeline_keys} xKey="week" height={200} colors={im.timeline_keys.map((k: string) => SERIES[SRC.indexOf(k) % SERIES.length])} />
                  </Card>
                  <Card title="Top-level domains used"><HBar data={im.tlds} label="tld" value="n" /></Card>
                </div>
                <Card title="Every lookalike of this brand" sub="pre-block in mail and web gateways; request takedown of resolving ones"
                  right={<a className="btn" href={`/api/iocs/export?days=3650&org=${o.id}`}><ExternalLink size={12} />Blocklist CSV</a>}>
                  <Table rows={im.rows} max={200} cols={[
                    { key: 'host', label: 'Domain', render: (r: any) => <span className="mono">{r.host}</span> },
                    { key: 'source', label: 'Source', render: (r: any) => <span className="pill"><span className="dot" style={{ background: SERIES[SRC.indexOf(r.source) % SERIES.length] }} />{r.source}</span> },
                    { key: 'lure', label: 'Lure theme' },
                    { key: 'live', label: 'Resolves', render: (r: any) => (r.checked ? (r.live ? <b>yes</b> : 'no') : <span className="muted">not checked</span>), sort: (r: any) => (r.live ? 1 : 0) },
                    { key: 'publisher', label: 'Reported by', render: (r: any) => <span className="muted">{r.publisher}</span> },
                    { key: 'published', label: 'Date', render: (r: any) => day(r.published) }]} />
                </Card>
              </>)}
          </div>
        )
      })()}

      {tab === 'summary' && <div style={{ marginBottom: 14 }}><OrgBrief id={id!} showOpen={false} /></div>}
      {tab === 'summary' && (
        <div className="grid g2">
          <div className="stack" style={{ gap: 14 }}>
            <Card title="Act first" sub="open findings by their act-by date — the deadline rule reflects how fast attackers exploit each class">
              {(() => {
                const due = (data.findings as any[]).filter(f => f.act_by).sort((a, b) => a.act_by.localeCompare(b.act_by)).slice(0, 8)
                return due.length ? (
                  <div className="feed">{due.map(f => (
                    <div key={f.id} className="feed-item" style={{ gridTemplateColumns: 'auto 1fr auto' }}>
                      <ActBy ts={f.act_by} rule={f.deadline_rule} />
                      <div><div className="t clamp2">{f.title}</div><div className="m"><Sev level={f.severity} rule={f.rule_id} compact /><span className="mono">{f.rule_id}</span></div></div>
                      {f.evidence_url?.startsWith('http') ? <SourceLink url={f.evidence_url} /> : <span />}
                    </div>))}</div>) : <Empty>No open Critical, High or Medium finding.</Empty>
              })()}
            </Card>
            <Card title="Why this level" sub="the most severe active findings and the rule behind each">
              <FindingList rows={data.findings.filter((f: any) => f.severity !== 'low').slice(0, 6)} empty="No Critical, High or Medium findings." />
            </Card>
          </div>
          <div className="stack" style={{ gap: 14 }}>
            <Card title="Incidents that could reach this organisation" sub="fastest-moving first — spreading, or exploited within 7 days of disclosure · from the Incidents & impact linkage"
              right={data.impacts.some((m: any) => m.fast) ? <a className="srclink" onClick={() => nav('/speed')}>Speed & spread →</a> : undefined}>
              {!data.impacts.length ? <Empty>Not linked to any current incident.</Empty> : (
                <div className="feed">{data.impacts.slice(0, 10).map((m: any, i: number) => (
                  <div key={i} className="feed-item clickable" style={{ gridTemplateColumns: 'auto 1fr' }} onClick={() => nav(`/incidents/${m.id}`)}>
                    <Sev level={m.severity} compact />
                    <div><div className="t clamp2">{m.title}</div>
                      <div className="m"><span className="pill">{LT[m.link_type]}</span>
                        {m.velocity?.spreading && <span className="pill" title="3+ independent publishers within 72 hours of the first report">spreading · {m.velocity.publishers_72h} publishers in 72h</span>}
                        {m.velocity?.kev_lag != null && m.velocity.kev_lag <= 7 && <span className="pill" title="CVE disclosure → CISA KEV">{m.velocity.kev_lag <= 0 ? 'zero-day' : `exploited ${m.velocity.kev_lag}d after disclosure`}</span>}
                        <When ts={m.last_seen} /></div>
                      <div className="m"><span className="clamp2">{m.reason}</span></div></div>
                  </div>))}</div>)}
            </Card>
            {data.identity?.providers?.length > 0 && (
              <Card title="Identity attacks in current reporting" sub={`context, not a finding — public DNS shows ${data.identity.providers.join(', ')}`}>
                {!data.identity.items.length ? <Empty>No device-code, token-theft or MFA-bypass reporting in the last 30 days.</Empty> : (
                  <div className="feed">{data.identity.items.slice(0, 5).map((i: any) => (
                    <div key={i.id} className="feed-item"><span className="pill">{i.publisher}</span><div><div className="t clamp2">{i.title}</div><div className="m"><When ts={i.published} /></div></div><SourceLink url={i.url} /></div>))}</div>)}
                <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>Preventive checks: block the device-code flow where it is not needed (Conditional Access), enable token protection and sign-in risk policies, and review OAuth app consents.</div>
              </Card>)}
            <Card title="Critical assets" sub="internet-facing identity, remote-access, mail, file-transfer, admin and customer systems (from public DNS / CT)">
              {!data.critical_assets.length ? <Empty>{scanned ? 'None identified from public hostnames.' : 'Available after the first surface scan.'}</Empty> : (
                <Table rows={data.critical_assets} max={12} cols={[
                  { key: 'class', label: 'Class', render: (a: any) => <span className="pill">{a.class}</span> },
                  { key: 'host', label: 'Host', render: (a: any) => <span className="mono">{a.host}</span> },
                  { key: 'product', label: 'Product / provider', render: (a: any) => a.product || a.provider || <span className="muted">—</span> },
                ]} />)}
            </Card>
            <Card title="Who is targeting organisations like this" sub={`extortion groups hitting ${o.sector || 'this sector'} in ${countryName(o.country)} (90 days) · CrowdStrike targeting`}>
              {data.threat.sector_actors.length ? <HBar data={data.threat.sector_actors} label="actor" value="victims" onClick={d => nav(`/adversaries/rw-${String(d.actor).toLowerCase()}`)} /> : <Empty>No sector-matched leak-site victims recently.</Empty>}
              {data.threat.crowdstrike_targeting.length > 0 && (
                <div className="row wrap" style={{ gap: 6, marginTop: 10 }}>
                  <span className="muted" style={{ fontSize: 12 }}>CrowdStrike lists these adversaries as targeting {countryName(o.country)} / this industry:</span>
                  {data.threat.crowdstrike_targeting.map((a: any) => <span key={a.id} className="pill btn" onClick={() => nav(`/adversaries/${a.id}`)}>{a.crowdstrike || a.name}</span>)}
                </div>)}
            </Card>
          </div>
        </div>
      )}

      {tab === 'assets' && (
        <div className="stack" style={{ gap: 14 }}>
          <div className="grid g4">
            <Stat label="Hostnames in certificate logs" value={compact(fp.ct_count)} hint={fp.domain?.attrs?.ct_source ? `via ${fp.domain.attrs.ct_source}` : 'awaiting scan'} />
            <Stat label="Public IP addresses resolved" value={fp.ips.length} hint={`${fp.ips.filter((i: any) => i.owned).length} in organisation-owned networks`} />
            <Stat label="Owned / declared IP ranges" value={fp.prefixes.length} hint="SPF ip4 + ASN registered to the org" />
            <Stat label="Direct subsidiaries (GLEIF)" value={fp.group?.direct_children ?? fp.subsidiaries.length} hint={fp.parent ? `ultimate parent: ${fp.parent.name}` : 'group structure'} />
          </div>
          <div className="grid g2">
            <Card title="Cloud environments" sub="public IPs attributed with the providers' official range files">
              {data.cloud.length ? <HBar data={data.cloud} label="provider" value="ips" /> : <Empty>{scanned ? 'No resolved IPs.' : 'Awaiting scan.'}</Empty>}
            </Card>
            <Card title="Critical assets" sub="by class">
              {data.critical_assets.length ? <HBar data={Object.entries(data.critical_assets.reduce((a: any, x: any) => ({ ...a, [x.class]: (a[x.class] || 0) + 1 }), {})).map(([k, n]) => ({ k, n }))} label="k" value="n" /> : <Empty>None identified.</Empty>}
            </Card>
          </div>
          <Card title="Public hostnames" sub="resolved via DNS-over-HTTPS · provider from CNAME · edge product from name">
            <Table rows={fp.host_list} max={200} empty="Awaiting scan." cols={[
              { key: 'host', label: 'Host', render: (h: any) => <span className="mono">{h.host}</span> },
              { key: 'ips', label: 'Addresses', render: (h: any) => <span className="mono muted">{(h.ips || []).join(', ') || '—'}</span> },
              { key: 'cname', label: 'CNAME / provider', render: (h: any) => h.cname ? <><span className="mono">{h.cname}</span>{h.cdn && <div className="muted">{h.cdn}</div>}</> : '—' },
              { key: 'edge', label: 'Edge product', render: (h: any) => h.edge ? <span className="pill">{h.edge[1]}</span> : '' },
              { key: 'dangling', label: '', render: (h: any) => h.dangling ? <Sev level="high" /> : '' },
            ]} />
          </Card>
          <div className="grid g2">
            <Card title="Owned & declared IP space" sub="used to attribute compromised-IP listings">
              <Table rows={fp.prefixes} max={80} empty="No owned ranges identified." cols={[{ key: 'cidr', label: 'Range', render: (r: any) => <span className="mono">{r.cidr}</span> }, { key: 'provenance', label: 'Why it is attributed' }]} />
            </Card>
            <Card title="Corporate group (GLEIF Level 2)" sub={fp.parent ? `Ultimate parent: ${fp.parent.name}` : 'direct subsidiaries'}>
              <Table rows={fp.subsidiaries} max={80} empty="No subsidiary records (or not yet collected)." cols={[
                { key: 'name', label: 'Subsidiary', render: (s: any) => <SourceLink url={s.url} label={s.name} /> },
                { key: 'country', label: 'Country', render: (s: any) => countryName(s.country) }, { key: 'city', label: 'City' }]} />
            </Card>
          </div>
        </div>
      )}

      {tab === 'third' && (
        <div className="grid g-main-side">
          <Card title="Software, services & third parties" sub="every tile is a provider evidenced in public DNS (MX, NS, SPF, TXT verification, CNAME), one tile per provider, grouped under its category · ⚠ + outline = an active issue at that provider reaching this organisation · click for the issue, or for the other monitored organisations that use it">
            {Object.keys(data.dependencies).length ? (
              <>
                <div style={{ height: 520 }}>
                  <ResponsiveTreeMap data={tpTree as any} identity="id" value="value" leavesOnly={false} innerPadding={4} outerPadding={4}
                    enableParentLabel parentLabelPosition="top" parentLabelSize={20} parentLabelPadding={6} parentLabelTextColor={INK2 as any}
                    parentLabel={(n: any) => (n.id === 'deps' ? '' : n.id)} orientLabel={false}
                    label={(n: any) => (n.data?.issue ? `⚠ ${n.id}` : n.id)} labelSkipSize={34}
                    colors={(n: any) => (n.data?.cat ? catColor(n.data.cat) : EMPTY)} nodeOpacity={1}
                    borderWidth={2} borderColor={((n: any) => (n.data?.issue ? INK : SURFACE)) as any}
                    labelTextColor={((n: any) => onFill(n.color)) as any} theme={nivoTheme as any} animate motionConfig="gentle"
                    onClick={(n: any) => { if (!n.data?.cat) return; n.data.issue ? nav(`/incidents/${n.data.issue.id}`) : nav(`/orgs?provider=${encodeURIComponent(n.id)}`) }}
                    tooltip={({ node }: any) => (node.data?.cat ? <div className="tip"><strong>{node.id}</strong><div>{node.data.cat} · {node.data.n} DNS record{node.data.n === 1 ? '' : 's'}</div>
                      {node.data.issue ? <div><Sev level={node.data.issue.severity} /> {node.data.issue.title}</div> : <div className="muted">click: other monitored organisations using it</div>}</div>
                      : <div className="tip"><strong>{node.id}</strong></div>)} />
                </div>
                {Object.keys(data.provider_issues || {}).length > 0 && (
                  <div style={{ marginTop: 12 }}>
                    <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>Active issues at this organisation's providers</div>
                    <div className="feed">{Object.entries(data.provider_issues).map(([v, p]: any) => (
                      <div key={v} className="feed-item clickable" style={{ gridTemplateColumns: 'auto 1fr' }} onClick={() => nav(`/incidents/${p.id}`)}>
                        <Sev level={p.severity} compact />
                        <div><div className="t clamp2"><b>{v}</b> — {p.title}</div><div className="m"><span className="pill">{p.kind}</span>
                          <a className="srclink" onClick={e => { e.stopPropagation(); nav(`/orgs?provider=${encodeURIComponent(v)}`) }}>other organisations using {v}</a></div></div>
                      </div>))}</div>
                  </div>)}
              </>) : <Empty>{scanned ? 'No providers identified.' : 'Awaiting scan.'}</Empty>}
          </Card>
          <Card title="Evidence" sub="the exact public records">
            <div className="stack" style={{ gap: 12, maxHeight: 520, overflowY: 'auto' }}>
              {Object.entries(data.dependencies).map(([c, vs]: any) => (
                <div key={c}>
                  <div className="muted" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.08em' }}>{c}</div>
                  {vs.map((v: any) => <div key={v.vendor} style={{ padding: '4px 0' }}><b>{v.vendor}</b><div className="mono muted" style={{ fontSize: 11 }}>{v.evidence.slice(0, 3).join(' · ')}</div></div>)}
                </div>
              ))}
              <FindingList rows={catFindings(['software'])} empty="No provider currently has an active incident." />
            </div>
          </Card>
        </div>
      )}

      {tab === 'exposure' && (
        <div className="stack" style={{ gap: 14 }}>
          <div className="grid g2">
            <Card title="Open ports on the organisation's own hosts" sub="from Shodan InternetDB (index lookup — nothing is scanned) · shared CDN/cloud IPs excluded">
              {data.ports.length ? <Columns data={data.ports.map((x: any) => ({ ...x, label: `${x.port}${x.service ? ' ' + x.service : ''}` }))} x="label" y="hosts" height={220} /> : <Empty>{scanned ? 'No indexed open ports.' : 'Awaiting scan.'}</Empty>}
            </Card>
            <Card title="Exposure & vulnerability findings">
              <FindingList rows={catFindings(['exposure', 'vulns'])} empty={scanned ? 'No exposed services or version-inferred CVEs on owned hosts.' : 'Awaiting scan.'} />
            </Card>
          </div>
          <Card title="Internet-facing addresses" sub="ports, software (CPE) and CVEs reported by the index">
            <Table rows={fp.ips} max={100} empty="Awaiting scan." cols={[
              { key: 'ip', label: 'IP', render: (r: any) => <SourceLink url={`https://internetdb.shodan.io/${r.ip}`} label={r.ip} /> },
              { key: 'hosts', label: 'Hostnames', render: (r: any) => <span className="mono muted" style={{ fontSize: 11.5 }}>{(r.hosts || []).join(', ')}</span> },
              { key: 'owner', label: 'Network', render: (r: any) => r.owned ? <span className="pill accent">Owned · AS{r.asn}</span> : r.cloud ? <span className="pill">{r.cloud.provider}</span> : <span className="muted">{r.as_name?.split(' - ')[0] || '—'}</span> },
              { key: 'ports', label: 'Ports', render: (r: any) => <span className="mono">{(r.ports || []).join(', ')}</span> },
              { key: 'cpes', label: 'Software', render: (r: any) => <span className="mono muted" style={{ fontSize: 11 }}>{(r.cpes || []).slice(0, 3).map((c: string) => c.replace('cpe:/', '')).join(', ')}</span> },
              { key: 'vulns', label: 'CVEs', num: true, render: (r: any) => (r.vulns || []).length || '', sort: (r: any) => (r.vulns || []).length },
            ]} />
          </Card>
        </div>
      )}

      {tab === 'compromise' && (<div className="stack" style={{ gap: 14 }}>
        {catFindings(['compromise']).length > 0 && (
          <Card title="Compromise findings" sub="owned IPs on blocklists, owned hostnames serving malware or ClickFix lures, and indicators published in threat reports">
            <FindingList rows={catFindings(['compromise'])} />
          </Card>)}
        <Card title="Compromised & malicious IP listings in owned space" sub={`checked ${day(data.compromised.checked)} against ${Object.keys(data.compromised.feeds || {}).length} feeds`}>
          {data.compromised.matches.length ? (
            <Table rows={data.compromised.matches} cols={[
              { key: 'listed', label: 'Listed address', render: (m: any) => <span className="mono">{m.listed}</span> }, { key: 'feed_name', label: 'Feed' },
              { key: 'category', label: 'Category' }, { key: 'footprint', label: 'Inside', render: (m: any) => <span className="mono">{m.footprint}</span> },
              { key: 'provenance', label: 'Why attributed' }, { key: 'url', label: '', render: (m: any) => <SourceLink url={m.url} label="feed" /> }]} />
          ) : (
            <div className="stack">
              <div className="row" style={{ gap: 10 }}><CheckCircle2 color="var(--good)" /><b>No address in this organisation's attributed IP space is currently listed.</b></div>
              <div className="ink2">Checked {compact(data.compromised.footprint_addresses)} addresses ({fp.prefixes.length} owned/declared ranges and {fp.ips.filter((i: any) => !i.shared || i.owned).length} resolved non-cloud IPs) against:</div>
              <Table rows={Object.values(data.compromised.feeds || {})} cols={[{ key: 'name', label: 'Feed', render: (f: any) => <SourceLink url={f.url} label={f.name} /> }, { key: 'entries', label: 'Entries', num: true }, { key: 'category', label: 'Category' }, { key: 'licence', label: 'Licence' }]} />
              <div className="muted" style={{ fontSize: 12 }}>Shared cloud / CDN addresses are excluded so a customer is never blamed for a neighbour's host. Absence of listings is not proof of absence of compromise.</div>
            </div>
          )}
        </Card>
      </div>)}

      {tab === 'events' && (
        <div className="stack" style={{ gap: 14 }}>
          <div className="grid g2">
            <Card title="Dark web, breaches & credential exposure"><FindingList rows={catFindings(['darkweb'])} empty="Not listed on leak sites, dark-web claims or breach catalogues; no infostealer exposure found." /></Card>
            <Card title="Incidents, disclosures, targeting & AI"><FindingList rows={catFindings(['disclosure', 'chatter', 'ai'])} empty="No disclosures, named reporting or targeting." /></Card>
            <Card title="Provider incidents that reach this organisation" sub="provider dependency (public DNS) or named as an affected customer">
              <FindingList rows={(data.findings as any[]).filter(f => f.rule_id === 'TP-VENDOR-INC' || f.rule_id === 'TP-NAMED-CUSTOMER')} empty="No provider this organisation uses has a breach or compromise in the last 30 days." />
            </Card>
          </div>
          {(data.impersonation?.total || 0) > 0 && (
            <Card className="clickable" onClick={() => setTab('impersonation')}>
              <div className="row" style={{ gap: 10 }}><b>{data.impersonation.total} lookalike domain{data.impersonation.total === 1 ? '' : 's'} of this brand</b>
                <span className="muted">({data.impersonation.live} resolving) — see the Impersonation tab for lures, sources, trend and the blocklist.</span></div>
            </Card>)}
          {stealer && (
            <Card title="Infostealer exposure" sub="Hudson Rock community data — counts only, no credentials" right={<SourceLink url={stealer.url} label="Hudson Rock" />}>
              <div className="grid g4" style={{ marginBottom: 12 }}>
                <Stat label="Employee devices" value={compact(stealer.extra?.employees)} hint={`last ${day(stealer.extra?.last_employee)}`} />
                <Stat label="Customer / user devices" value={compact(stealer.extra?.users)} hint={`last ${day(stealer.extra?.last_user)}`} />
                <Stat label="Third-party logins" value={compact(stealer.extra?.third_parties)} />
                <Stat label="Corporate apps seen" value={(stealer.extra?.applications || []).length} hint={(stealer.extra?.applications || []).slice(0, 5).join(', ')} />
              </div>
              {Object.keys(stealer.extra?.families || {}).length > 0 && <HBar data={Object.entries(stealer.extra.families).map(([f, n]) => ({ f, n }))} label="f" value="n" />}
            </Card>)}
          <Card title="Named in reporting & chatter" sub="news, research, advisories, dark-web reporting and community posts mentioning this organisation">
            <Table rows={data.mentions} max={60} empty="No mentions in the collected reporting." cols={[
              { key: 'published', label: 'When', render: (m: any) => <When ts={m.published} /> },
              { key: 'title', label: 'Item', render: (m: any) => <><div>{m.title}</div><div className="muted" style={{ fontSize: 12 }}>{m.publisher} · {m.pub_type}</div></> },
              { key: 'url', label: '', render: (m: any) => <SourceLink url={m.url} /> }]} />
          </Card>
          <Card title="Leak-site, breach and targeting records">
            <Table rows={data.leaks.filter((l: any) => l.kind !== 'stealer')} empty="None." cols={[
              { key: 'kind', label: 'Type', render: (l: any) => <span className="pill">{({ leaksite: 'Leak site', forum: 'Dark-web claim', breach: 'Breach', ddos: 'DDoS target' } as any)[l.kind] || l.kind}</span> },
              { key: 'title', label: 'Record' }, { key: 'match', label: 'Matched by', render: (l: any) => <span className="muted">{l.match}</span> },
              { key: 'published', label: 'When', render: (l: any) => day(l.published) }, { key: 'url', label: '', render: (l: any) => <SourceLink url={l.url} /> }]} />
          </Card>
        </div>
      )}

      {tab === 'hygiene' && (
        <div className="grid g-main-side">
          <Card title={`Email & domain security — ${d || ''}`} sub="read from public DNS through Google / Cloudflare DNS-over-HTTPS">
            {!fp.domain ? <Empty>Awaiting scan.</Empty> : (
              <div className="feed">
                <Check ok={!!hy.dmarc && hy.dmarc.p !== 'none'} warn={hy.dmarc?.p === 'quarantine' || hy.dmarc?.p === 'none'} label={`DMARC${hy.dmarc ? ` (p=${hy.dmarc.p})` : ''}`} detail={hy.dmarc?.record} url={dohUrl(`_dmarc.${d}`, 'TXT')} />
                <Check ok={!!hy.spf && hy.spf.all === '-'} warn={!!hy.spf} label={`SPF${hy.spf ? ` (${hy.spf.all}all, ~${hy.spf.lookups} lookups)` : ''}`} detail={hy.spf?.record} url={dohUrl(d, 'TXT')} />
                <Check ok={(hy.dkim_selectors || []).length > 0} warn label="DKIM (common selectors)" detail={(hy.dkim_selectors || []).join(', ') || 'no key found on common selectors — may use custom selectors'} />
                <Check ok={!!hy.dnssec} label="DNSSEC" url={dohUrl(d, 'DS')} />
                <Check ok={!!hy.mta_sts} label="MTA-STS" url={dohUrl(`_mta-sts.${d}`, 'TXT')} />
                <Check ok={!!hy.tls_rpt} label="SMTP TLS reporting" url={dohUrl(`_smtp._tls.${d}`, 'TXT')} />
                <Check ok={(hy.caa || []).length > 0} label="CAA" detail={(hy.caa || []).join(' · ')} url={dohUrl(d, 'CAA')} />
                <Check ok label="Mail exchangers" detail={(hy.mx || []).join(', ')} url={dohUrl(d, 'MX')} />
                <Check ok label="Name servers" detail={(hy.ns || []).join(', ')} url={dohUrl(d, 'NS')} />
              </div>)}
          </Card>
          <Card title="Hygiene findings"><FindingList rows={catFindings(['hygiene'])} empty="All checked controls present." /></Card>
        </div>
      )}

      {tab === 'prevent' && (() => {
        const acts: any[] = data.actions || []
        const openA = acts.filter(a => a.open)
        const closed = acts.filter(a => a.status === 'resolved' && a.verified_closed_at)
        const pv = data.prevent
        return (
          <div className="stack" style={{ gap: 14 }}>
            <div className="grid g4">
              <Stat label="Open actions · now" value={openA.length} hint={`${openA.filter(a => a.level === 'critical').length} Critical · ${openA.filter(a => a.level === 'high').length} High`} />
              <Stat label="Overdue · now" value={openA.filter(a => a.overdue).length} hint="past the act-by date of their deadline rule" />
              <Stat label="Verified closed" value={closed.length} hint="fixes AEGIS re-observed as gone" />
              <Stat label="Controls in place" value={pv?.scanned ? `${pv.controls.filter((c: any) => c.has).length} / ${pv.controls.filter((c: any) => c.measured).length}` : '—'} hint={pv?.scanned ? `measured passively · sector: ${pv.sector}` : 'awaiting the surface scan'} />
            </div>
            <div className="grid g-main-side">
              <Card title="Preventive controls — this organisation, its sector and the estate" sub="✓ in place · ✕ missing · — not measured · bars: share of the sector and of all monitored organisations with the control">
                {!pv?.scanned ? <Empty>Awaiting the surface scan.</Empty> : (
                  <div className="stack" style={{ gap: 9 }}>
                    {pv.controls.map((c: any) => (
                      <div key={c.id} style={{ display: 'grid', gridTemplateColumns: '22px minmax(0,1.5fr) minmax(0,1fr) minmax(0,1fr)', gap: 10, alignItems: 'center', fontSize: 12.5 }}>
                        <b style={{ color: c.has ? 'var(--good)' : c.measured ? 'var(--high)' : 'var(--muted)' }} aria-label={c.has ? 'in place' : c.measured ? 'missing' : 'not measured'}>{c.has ? '✓' : c.measured ? '✕' : '—'}</b>
                        <div><b>{c.label}</b><div className="muted" style={{ fontSize: 11.5 }}>prevents: {c.prevents}</div></div>
                        <div title={`${c.sector}: ${c.sector_pct ?? '—'}% of ${c.sector_n ?? 0}`}><div className="muted" style={{ fontSize: 11 }}>sector {c.sector_pct ?? '—'}%</div>
                          <div style={{ height: 6, background: 'var(--hair)', borderRadius: 3 }}><div style={{ width: `${c.sector_pct || 0}%`, height: '100%', background: SERIES[1], borderRadius: 3 }} /></div></div>
                        <div title={`all monitored organisations: ${c.estate_pct ?? '—'}%`}><div className="muted" style={{ fontSize: 11 }}>estate {c.estate_pct ?? '—'}%</div>
                          <div style={{ height: 6, background: 'var(--hair)', borderRadius: 3 }}><div style={{ width: `${c.estate_pct || 0}%`, height: '100%', background: SERIES[0], borderRadius: 3 }} /></div></div>
                      </div>))}
                  </div>)}
              </Card>
              <Card title="Prove a fix" sub="closure is verified by re-observing the public record">
                <div className="stack" style={{ gap: 10, fontSize: 13 }}>
                  <div>When an owner fixes something, ask AEGIS to look again. If the finding is gone, its action closes itself as <b>verified closed</b>; if it returns later, the action reopens.</div>
                  <button className="btn primary" onClick={async () => { await api(`/orgs/${id}/scan`, { method: 'POST' }); alert('Re-check queued — the passive scan and the next pipeline run will update the actions.') }}>Re-check now</button>
                  <a className="srclink" onClick={() => nav('/prevent')}>Every organisation's action queue →</a>
                </div>
              </Card>
            </div>
            <Card title="Actions for this organisation" sub="open first · expand a row for the playbook and history · status changes are recorded with your name">
              {!acts.length ? <Empty>No Critical, High or Medium findings — nothing to action.</Empty>
                : <ActionTable rows={acts} showOrg={false} onChanged={() => refetch()} />}
            </Card>
          </div>)
      })()}

      {tab === 'findings' && (
        <Card className="flush">
          <Table rows={cat ? data.findings.filter((f: any) => f.category === cat) : data.findings} max={400} empty="No findings."
            cols={[
              { key: 'severity', label: 'Level', render: (f: any) => <Sev level={f.severity} rule={f.rule_id} />, sort: (f: any) => ['critical', 'high', 'medium', 'low'].indexOf(f.severity) },
              { key: 'category', label: 'Category', render: (f: any) => <span className="ink2">{(data.categories.find((c: any) => c[0] === f.category) || [])[1]}</span> },
              { key: 'title', label: 'Finding', render: (f: any) => <><div>{f.title}</div><div className="muted" style={{ fontSize: 12 }}>{f.detail}</div></> },
              { key: 'rule_id', label: 'Rule', render: (f: any) => <span className="mono" title={f.rule_id}>{f.rule_id}</span> },
              { key: 'observed', label: 'Observed', render: (f: any) => day(f.observed) },
              { key: 'evidence_url', label: '', render: (f: any) => f.evidence_url?.startsWith('http') ? <SourceLink url={f.evidence_url} /> : null },
            ]} />
        </Card>
      )}
    </div>
  )
}
