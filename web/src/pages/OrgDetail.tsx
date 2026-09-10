import { useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { motion } from 'motion/react'
import { ResponsiveCirclePacking } from '@nivo/circle-packing'
import { RefreshCw, CheckCircle2, XCircle, MinusCircle, ExternalLink } from 'lucide-react'
import { useApi, api } from '../lib/api'
import { Card, Sev, Conf, Why, Empty, When, SourceLink, Tabs, Table, SevCounts, Stat, useRules, usePlaybooks } from '../components/ui'
import { HBar, Columns } from '../components/charts'
import { gloss } from '../lib/glossary'
import { SEV_COLOR, SERIES, nivoTheme, EMPTY, SURFACE, onFill } from '../lib/chartTheme'
import { countryName, day, compact } from '../lib/format'

type Tab = 'summary' | 'prevent' | 'assets' | 'third' | 'exposure' | 'compromise' | 'events' | 'hygiene' | 'findings'
const CAT_TAB: Record<string, Tab> = { footprint: 'assets', critical: 'assets', cloud: 'assets', software: 'third', exposure: 'exposure', vulns: 'exposure',
  compromise: 'compromise', darkweb: 'events', chatter: 'events', hygiene: 'hygiene', disclosure: 'events', ai: 'events' }
const LT: Record<string, string> = { DIRECT: 'Named victim', GROUP: 'Corporate group', DEPENDENCY: 'Provider dependency', EXPOSED_PRODUCT: 'Exposed product', TARGETING: 'Sector targeting' }

function Check({ ok, warn, label, detail, url, state, linkLabel }:
  { ok: boolean; warn?: boolean; label: string; detail?: string; url?: string; state?: string; linkLabel?: string }) {
  const Icon = ok ? CheckCircle2 : warn ? MinusCircle : XCircle
  const color = ok ? 'var(--good)' : warn ? 'var(--medium)' : 'var(--high)'
  return (
    <div className="feed-item" style={{ gridTemplateColumns: 'auto 1fr auto' }}>
      <Icon size={16} color={color} />
      <div><div className="t">{gloss(label)} <span className="muted" style={{ fontWeight: 400 }}>· {state || (ok ? 'present' : warn ? 'partial' : 'missing')}</span></div>{detail && <div className="m mono" style={{ wordBreak: 'break-all' }}>{detail}</div>}</div>
      {url ? <SourceLink url={url} label={linkLabel || 'DNS record'} /> : <span />}
    </div>
  )
}

const STATUS_LABEL: Record<string, string> = {
  new: 'New', acknowledged: 'Acknowledged', in_progress: 'In progress',
  resolved: 'Resolved', accepted_risk: 'Accepted risk', false_positive: 'False positive',
}

/** One action: what it prevents, who owns it, when it is due, and how to move it along. */
function Action({ a, onChanged }: { a: any; onChanged: () => void }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const book = a.playbook
  const move = async (status: string) => {
    // the server requires these where the change suppresses a finding that is still true
    const needsReason = status === 'accepted_risk' || status === 'false_positive'
    const reason = needsReason ? window.prompt(`Why is this ${STATUS_LABEL[status].toLowerCase()}?`) : null
    if (needsReason && !reason) return
    const expires = status === 'accepted_risk' ? window.prompt('Accepted until when? (YYYY-MM-DD)') : null
    if (status === 'accepted_risk' && !expires) return
    const by = window.prompt('Your name, for the history') || ''
    setBusy(true); setErr('')
    try {
      await api(`/actions/${a.id}/status`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, reason, expires, by }) })
      onChanged()
    } catch (e: any) { setErr(String(e.message || e)) } finally { setBusy(false) }
  }
  const next: string[] = a.status === 'new' ? ['acknowledged', 'in_progress', 'accepted_risk', 'false_positive']
    : a.status === 'acknowledged' ? ['in_progress', 'accepted_risk', 'false_positive']
      : a.status === 'in_progress' ? ['accepted_risk', 'false_positive'] : []
  return (
    <div className="feed-item" style={{ gridTemplateColumns: '1fr', gap: 6 }}>
      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        <Sev level={a.level} rule={a.rule_id} />
        <Conf level={a.confidence} />
        <b style={{ flex: 1, minWidth: 180 }}>{a.title}</b>
        {a.owner_role && <span className="pill">{a.owner_role}</span>}
        {book && <span className="pill" title={`about ${book.effort_label}`}>{book.effort}</span>}
        <span className={`pill${a.overdue ? '' : ''}`} style={a.overdue ? { color: 'var(--high)' } : undefined}>
          {STATUS_LABEL[a.status] || a.status}{a.due ? ` · due ${String(a.due).slice(0, 10)}` : ''}{a.overdue ? ' · overdue' : ''}
        </span>
        <button className="pill btn" onClick={() => setOpen(o => !o)}>{open ? 'Hide' : 'How to fix'}</button>
      </div>
      {book && <div className="m" style={{ color: 'var(--ink-2)' }}><b>Prevents:</b> {gloss(book.prevents)}</div>}
      {a.reopened > 0 && <div className="m" style={{ color: 'var(--medium)' }}>Reopened {a.reopened}× — the finding came back after being closed.</div>}
      {a.verified_closed_at && <div className="m muted">Verified closed {String(a.verified_closed_at).slice(0, 10)} — the finding is no longer produced.</div>}
      {open && (
        <div className="stack" style={{ gap: 6, paddingLeft: 4, borderLeft: '2px solid var(--hair-2)', marginLeft: 2 }}>
          {book && <ol style={{ margin: 0, paddingLeft: 18 }}>{book.steps.map((st: string, i: number) => <li key={i} style={{ marginBottom: 3 }}>{gloss(st)}</li>)}</ol>}
          {book?.controls?.length > 0 && <div className="m muted">Indicative control references: {book.controls.join(' · ')}</div>}
          {next.length > 0 && (
            <div className="row wrap" style={{ gap: 6 }}>
              <span className="m muted">Move to:</span>
              {next.map(st => <button key={st} className="pill btn" disabled={busy} onClick={() => move(st)}>{STATUS_LABEL[st]}</button>)}
            </div>
          )}
          {err && <div className="m" style={{ color: 'var(--critical)' }}>{err}</div>}
          {(a.history || []).length > 0 && (
            <div className="m muted">{(a.history as any[]).slice(-3).map((h, i) =>
              <div key={i}>{String(h.at).slice(0, 10)} · {STATUS_LABEL[h.status] || h.status} · {h.by}{h.reason ? ` — ${h.reason}` : ''}</div>)}</div>
          )}
        </div>
      )}
    </div>
  )
}

// preventable findings are ordered worst-first, then by how much work the fix is
const SEV_RANK = ['critical', 'high', 'medium', 'low']
const EFFORT_ORDER: Record<string, number> = { S: 0, M: 1, L: 2 }

function FindingList({ rows, empty }: { rows: any[]; empty?: string }) {
  if (!rows.length) return <Empty>{empty || 'No findings in this category.'}</Empty>
  return (
    <div className="feed">
      {rows.map(f => (
        <div key={f.id} className="feed-item" style={{ gridTemplateColumns: 'auto 1fr auto' }}>
          <Sev level={f.severity} rule={f.rule_id} />
          <div>
            <div className="t">{f.title} <Conf level={f.confidence} /></div>
            {f.detail && <div className="m">{f.detail}</div>}
            <div style={{ marginTop: 6 }}><Why rule={f.rule_id} level={f.severity} /></div>
            <div className="m" style={{ marginTop: 4 }}><span>observed {day(f.observed)}</span><span>first seen <When ts={f.first_seen} /></span><span className="mono">{f.source_id}</span></div>
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
  const [tab, setTab] = useState<Tab>('summary')
  const [cat, setCat] = useState<string | null>(null)
  const [queued, setQueued] = useState(false)
  useRules()
  const byCat = useMemo(() => {
    const m: Record<string, any[]> = {}
    for (const f of data?.findings || []) (m[f.category] ||= []).push(f)
    return m
  }, [data])
  // every hook must run before the loading return below, or the hook count changes between renders
  const acts: any[] = useMemo(() => (data?.actions as any[]) || [], [data])
  const openActs = useMemo(() => acts.filter(a => a.open), [acts])
  const byOwner = useMemo(() => {
    const m: Record<string, any[]> = {}
    for (const a of openActs) (m[a.owner_role || 'Unassigned'] ||= []).push(a)
    return Object.entries(m).sort((a, b) => b[1].length - a[1].length)
  }, [openActs])
  if (!data) return <div className="muted">Loading organisation…</div>
  const o = data.org, p = data.posture, fp = data.footprint
  const scanned = !!fp.scanned
  const catFindings = (cats: string[]) => (data.findings as any[]).filter(f => cats.includes(f.category))
  const packing = { id: 'deps', children: Object.entries(data.dependencies).map(([c, vs]: any, i) => ({ id: c, color: SERIES[i % SERIES.length], children: vs.map((v: any) => ({ id: `${v.vendor}`, value: v.evidence.length + 1, cat: c, color: SERIES[i % SERIES.length] })) })) }
  const hy = fp.domain?.attrs?.hygiene || {}
  const d = fp.domain?.value || o.domain
  const rdap = fp.domain?.attrs?.rdap || null
  const rdapUrl = d ? `https://rdap.org/domain/${d}` : undefined
  const expiryDays = rdap?.expires ? Math.floor((Date.parse(rdap.expires) - Date.now()) / 86400000) : null
  const lookalikes: any[] = fp.lookalikes || []
  const prevent = data.prevent || { scanned: false, controls: [] }
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
        { id: 'summary', label: 'Overview' }, { id: 'prevent', label: 'Prevent' }, { id: 'assets', label: 'Assets & cloud' }, { id: 'third', label: 'Software & third parties' },
        { id: 'exposure', label: 'Exposure & vulnerabilities' }, { id: 'compromise', label: 'Compromised IPs' }, { id: 'events', label: 'Dark web & incidents' },
        { id: 'hygiene', label: 'Email & domain' }, { id: 'findings', label: 'All findings', count: data.findings.length }]} />

      {tab === 'summary' && (
        <div className="grid g2">
          <Card title="Why this level" sub="the most severe active findings and the rule behind each">
            <FindingList rows={data.findings.filter((f: any) => f.severity !== 'low').slice(0, 6)} empty="No Critical, High or Medium findings." />
          </Card>
          <div className="stack" style={{ gap: 14 }}>
            <Card title="Incidents that could reach this organisation" sub="from the Incidents & impact linkage">
              {!data.impacts.length ? <Empty>Not linked to any current incident.</Empty> : (
                <div className="feed">{data.impacts.slice(0, 10).map((m: any, i: number) => (
                  <div key={i} className="feed-item clickable" style={{ gridTemplateColumns: 'auto 1fr' }} onClick={() => nav(`/incidents/${m.id}`)}>
                    <Sev level={m.severity} compact />
                    <div><div className="t clamp2">{m.title}</div><div className="m"><span className="pill">{LT[m.link_type]}</span><span className="clamp2">{m.reason}</span><When ts={m.last_seen} /></div></div>
                  </div>))}</div>)}
            </Card>
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

      {tab === 'prevent' && (
        <div className="stack" style={{ gap: 14 }}>
          <div className="grid g4">
            <Stat label="Open actions" value={openActs.length} hint="Critical, High and Medium — Low stays inventory" />
            <Stat label="Overdue" value={openActs.filter(a => a.overdue).length} hint="past the due date for their level" />
            <Stat label="Quick wins" value={openActs.filter(a => a.playbook?.effort === 'S').length} hint="hours of work, not days" />
            <Stat label="Verified closed" value={acts.filter(a => a.verified_closed_at).length} hint="proved fixed by a later scan" />
          </div>

          <Card title="Controls, next to peers in the same sector"
            sub="adoption among monitored organisations — context for whether a gap is unusual or normal">
            {!prevent.scanned ? <Empty>Awaiting scan.</Empty> : (
              <Table rows={prevent.controls} max={20} cols={[
                { key: 'label', label: 'Control' },
                { key: 'prevents', label: 'Prevents', render: (c: any) => <span className="muted">{gloss(c.prevents)}</span> },
                { key: 'has', label: 'This organisation', width: 145, render: (c: any) => !c.measured
                  ? <span className="muted" title="This check has not run for this organisation yet — it is not a finding either way">not checked yet</span>
                  : c.has ? <span className="pill">in place</span>
                    : <span className="pill" style={{ color: 'var(--medium)' }}>not in place</span> },
                { key: 'sector_pct', label: 'Sector', width: 120, num: true,
                  render: (c: any) => c.sector_pct === null || c.sector_pct === undefined ? <span className="muted">—</span>
                    : <span title={`${c.sector_pct}% of ${c.sector_n} monitored ${c.sector} organisations`}>{c.sector_pct}%</span> },
                { key: 'estate_pct', label: 'All monitored', width: 130, num: true,
                  render: (c: any) => c.estate_pct === null || c.estate_pct === undefined
                    ? <span className="muted">—</span> : <span className="muted">{c.estate_pct}%</span> },
              ]} />)}
          </Card>

          {byOwner.map(([owner, rows]) => (
            <Card key={owner} title={owner} sub={`${rows.length} open${rows.filter((r: any) => r.overdue).length ? ` · ${rows.filter((r: any) => r.overdue).length} overdue` : ''}`}>
              <div className="feed">{rows.map((a: any) => <Action key={a.id} a={a} onChanged={refetch} />)}</div>
            </Card>
          ))}
          {!openActs.length && <Card><Empty>No open actions. Low findings stay as inventory rather than becoming work.</Empty></Card>}
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
              <Table rows={fp.prefixes} max={80} empty="No owned ranges identified." cols={[
                { key: 'cidr', label: 'Range', render: (r: any) => <span className="mono">{r.cidr}</span> },
                { key: 'rpki', label: 'RPKI', width: 130, render: (r: any) => !r.rpki ? <span className="muted" title="Only prefixes announced by an ASN registered to this organisation are validated">—</span>
                  : r.rpki === 'valid' ? <span className="pill">valid</span>
                    : <Sev level={r.rpki === 'invalid' ? 'high' : 'medium'} rule={r.rpki === 'invalid' ? 'BGP-RPKI-INVALID' : 'BGP-RPKI-NONE'} /> },
                { key: 'provenance', label: 'Why it is attributed' }]} />
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
          <Card title="Software, services & third parties" sub="every bubble is a provider evidenced in public DNS (MX, NS, SPF, TXT verification, CNAME) — size = number of records">
            {Object.keys(data.dependencies).length ? (
              <div style={{ height: 520 }}>
                <ResponsiveCirclePacking data={packing as any} id="id" value="value" padding={4} leavesOnly={false}
                  colors={(n: any) => n.data.color || EMPTY} childColor={{ from: 'color', modifiers: [['brighter', 0.4]] } as any}
                  borderWidth={1} borderColor={SURFACE} enableLabels labelsSkipRadius={18} labelTextColor={((n: any) => onFill(n.color)) as any} label={(n: any) => n.id}
                  theme={nivoTheme as any} motionConfig="gentle"
                  tooltip={({ id, data: dd }: any) => <div className="tip"><strong>{id}</strong>{dd.cat && <div>{dd.cat}</div>}</div>} />
              </div>) : <Empty>{scanned ? 'No providers identified.' : 'Awaiting scan.'}</Empty>}
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

      {tab === 'compromise' && (
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
      )}

      {tab === 'events' && (
        <div className="stack" style={{ gap: 14 }}>
          <div className="grid g2">
            <Card title="Dark web, breaches & credential exposure"><FindingList rows={catFindings(['darkweb'])} empty="Not listed on leak sites, dark-web claims or breach catalogues; no infostealer exposure found." /></Card>
            <Card title="Incidents, disclosures, targeting & AI"><FindingList rows={catFindings(['disclosure', 'chatter', 'ai'])} empty="No disclosures, named reporting or targeting." /></Card>
          </div>
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
          <div className="stack" style={{ gap: 14 }}>
            <Card title="Domain lifecycle" sub="registry record via RDAP — the registrar lock and expiry date">
              {!rdap ? <Empty>{fp.domain ? 'No registry record retrieved for this domain.' : 'Awaiting scan.'}</Empty> : (
                <div className="feed">
                  <Check ok={!!rdap.locked} label="Registrar transfer lock" state={rdap.locked ? 'locked' : 'not locked'}
                    detail={(rdap.statuses || []).join(' · ') || 'no status published'} url={rdapUrl} linkLabel="RDAP record" />
                  <Check ok={expiryDays === null || expiryDays > 90} warn={expiryDays !== null && expiryDays > 30 && expiryDays <= 90}
                    label="Registration expiry"
                    state={expiryDays === null ? 'unknown' : expiryDays < 0 ? `expired ${Math.abs(expiryDays)} days ago` : `${expiryDays} days left`}
                    detail={rdap.expires ? `Expires ${String(rdap.expires).slice(0, 10)}` : undefined} url={rdapUrl} linkLabel="RDAP record" />
                  <Check ok label="Registrar" state={rdap.registrar ? 'on record' : 'unknown'} detail={rdap.registrar || undefined} url={rdapUrl} linkLabel="RDAP record" />
                </div>)}
            </Card>
            {lookalikes.length > 0 && (
              <Card title="Lookalike domains" sub="confusable variants generated locally, then resolved through public DNS" className="flush">
                <Table rows={lookalikes} max={25} cols={[
                  { key: 'domain', label: 'Domain', render: (l: any) => <span className="mono">{l.domain}</span> },
                  { key: 'mx', label: 'Accepts mail', render: (l: any) => (l.mx || []).length ? <span className="pill">MX</span> : <span className="muted">—</span> },
                  { key: 'ips', label: 'Resolves to', render: (l: any) => <span className="muted mono">{(l.ips || []).join(', ') || '—'}</span> },
                ]} />
              </Card>
            )}
            <Card title="Hygiene findings"><FindingList rows={catFindings(['hygiene'])} empty="All checked controls present." /></Card>
          </div>
        </div>
      )}

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
