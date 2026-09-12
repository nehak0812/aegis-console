import { useEffect, useState, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Zap } from 'lucide-react'
import { useApi } from '../lib/api'
import { useRange } from '../App'
import { Card, Sev, Table, Empty, SourceLink, When, ActBy, StoryStrip, PageSources } from '../components/ui'
import { Columns } from '../components/charts'
import { RaceChart, StackedBars, dueDays } from '../components/summaryviz'
import { SEV_COLOR, SERIES, NEUTRAL, INK2, MUTED, GRID, SURFACE } from '../lib/chartTheme'
import { day, pct } from '../lib/format'

const RANKV: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }
const LINK: Record<string, string> = { DIRECT: 'named victim', GROUP: 'corporate group', DEPENDENCY: 'uses the provider', NAMED_CUSTOMER: 'named customer', EXPOSED_PRODUCT: 'runs the product' }
const pc = (v?: number | null) => (v == null ? '—' : `${Math.round(v * 100)}%`)
const go = (id: string) => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })

/* ------------------------------------------------------------------ chapter frame */
function Chapter({ id, n, title, so, children }: { id: string; n: number; title: string; so: ReactNode; children: ReactNode }) {
  return (
    <section id={id} style={{ scrollMarginTop: 80, marginBottom: 22 }}>
      <div className="row" style={{ gap: 12, alignItems: 'flex-start', margin: '6px 0 12px' }}>
        <span style={{ flex: 'none', width: 28, height: 28, borderRadius: 999, display: 'grid', placeItems: 'center', background: 'var(--accent-wash)', color: 'var(--accent)', fontWeight: 700 }}>{n}</span>
        <div><h3 style={{ margin: 0, fontSize: 17 }}>{title}</h3><div className="ink2" style={{ fontSize: 13, marginTop: 2 }}>{so}</div></div>
      </div>
      {children}
    </section>
  )
}

/* ------------------------------------------------------------------ 2 · spreading: publishers over the first five days */
const LANE_H = 120
function SpreadLanes({ rows, onOpen }: { rows: any[]; onOpen: (id: string) => void }) {
  const cols = 'minmax(0, 2.3fr) minmax(0, 3fr) 150px'
  return (
    <div>
      <div className="lanes hide-sm" style={{ display: 'grid', gridTemplateColumns: cols, gap: 12, fontSize: 11.5, color: 'var(--muted)', padding: '0 6px 4px' }}>
        <span>Incident</span>
        <span className="row" style={{ justifyContent: 'space-between' }}>{[0, 24, 48, 72, 96, 120].map(h => <span key={h}>{h === 120 ? '120h+' : `${h}h`}</span>)}</span>
        <span style={{ textAlign: 'right' }}>Spread · reach</span>
      </div>
      {rows.map(s => (
        <div key={s.id} className="clickable lanes" onClick={() => onOpen(s.id)} title="Open the incident, its sources and every organisation link"
          style={{ display: 'grid', gridTemplateColumns: cols, gap: 12, alignItems: 'center', padding: '7px 6px', borderTop: '1px solid var(--hair)' }}>
          <div className="row" style={{ gap: 6, minWidth: 0 }}><Sev level={s.severity} compact /><span className="trunc" style={{ fontSize: 12.5 }} title={s.title}>{s.title}</span></div>
          <svg viewBox="0 0 500 22" style={{ width: '100%', height: 'auto', display: 'block' }}>
            <rect x={0} y={4} width={(72 / LANE_H) * 500} height={14} rx={7} fill={SERIES[0]} opacity={0.08} />
            <line x1={0} x2={500} y1={11} y2={11} stroke={GRID} />
            <line x1={(72 / LANE_H) * 500} x2={(72 / LANE_H) * 500} y1={0} y2={22} stroke={MUTED} strokeDasharray="3 3" />
            {(s.curve || []).map((c: any, i: number) => (
              <circle key={i} cx={4 + (Math.min(LANE_H, c.h) / LANE_H) * 492} cy={11} r={5} fill={c.h <= 72 ? SERIES[0] : NEUTRAL} stroke={SURFACE} strokeWidth={1.2}>
                <title>{`${c.publisher} · ${c.h <= 0 ? 'first report' : `+${Math.round(c.h)}h`}`}</title>
              </circle>))}
          </svg>
          <div style={{ textAlign: 'right', fontSize: 12 }}>
            {s.spreading ? <span className="pill">spreading</span> : <span className="muted">{s.publishers_72h} in 72h</span>}
            <div className="muted" style={{ marginTop: 2 }}>{s.reach ? `reaches ${s.reach} org${s.reach === 1 ? '' : 's'}` : 'no monitored org'}</div>
          </div>
        </div>))}
      <div className="muted" style={{ fontSize: 11.5, marginTop: 6 }}>Each dot is one independent publisher's first report, placed by hours after the first report. Dashed line and shading = the first 72 hours; “spreading” = 3 or more publishers inside it.</div>
    </div>
  )
}

/* ------------------------------------------------------------------ 3 · the deadline board */
const BOARD: [string, string][] = [['overdue', 'Overdue'], ['72h', 'Next 72 hours'], ['7d', 'This week'], ['30d', 'This month'], ['later', 'Later']]
function DeadlineBoard({ board, onOrg }: { board: any; onOrg: (id: string) => void }) {
  const [open, setOpen] = useState(false)
  const shown = open ? 60 : 10
  return (
    <>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10 }}>
        {BOARD.map(([k, label]) => {
          const b = board[k] || { n: 0, orgs: [] }
          const urgent = k === 'overdue' || k === '72h'
          return (
            <div key={k} style={{ background: 'var(--raised)', border: `1px solid ${urgent && b.n ? 'var(--accent)' : 'var(--hair)'}`, borderRadius: 10, padding: 10, minHeight: 120 }}>
              <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}><b style={{ fontSize: 12.5 }}>{label}</b><span className="pill">{b.n}</span></div>
              {!b.n ? <div className="muted" style={{ fontSize: 12 }}>none</div> : (
                <div className="stack" style={{ gap: 5 }}>
                  {b.orgs.slice(0, shown).map((o: any) => (
                    <div key={o.id} className="row clickable" style={{ gap: 6, fontSize: 12.5, minWidth: 0 }} onClick={() => onOrg(o.id)} title={`${o.rule || ''} · act by ${day(o.act_by)}`}>
                      <Sev level={o.severity} compact />
                      <span className="trunc" style={{ flex: 1 }}>{o.name}</span>
                      {o.fast && <Zap size={13} style={{ color: 'var(--accent)', flex: 'none' }} aria-label="in the path of a fast-moving threat" />}
                    </div>))}
                  {b.n > shown && <span className="muted" style={{ fontSize: 12 }}>+{b.n - shown} more</span>}
                </div>)}
            </div>)
        })}
      </div>
      <div className="row wrap" style={{ gap: 12, fontSize: 12, marginTop: 8 }}>
        <span className="row" style={{ gap: 4 }}><Zap size={13} style={{ color: 'var(--accent)' }} /> in the path of a fast-moving threat (listed first)</span>
        <span className="muted">Each organisation appears once, in the column of its earliest act-by date · current state · click to open</span>
        <a className="srclink" onClick={() => setOpen(o => !o)}>{open ? 'Show fewer' : 'Show more per column'}</a>
      </div>
    </>
  )
}

/* ------------------------------------------------------------------ 5 · early warning: EPSS slope */
function Slope({ rows, onPick }: { rows: any[]; onPick: (cve: string) => void }) {
  const top = rows.slice(0, 8)
  if (!top.length) return <Empty>No tracked, not-yet-exploited CVE is rising this week.</Empty>
  const W = 470, H = 240, XL = 60, XR = 230
  const max = Math.max(0.01, ...top.map(r => Math.max(r.epss, r.epss_7d)))
  const y = (v: number) => 22 + (1 - v / max) * (H - 50)
  const labels = top.map(r => ({ r, ly: y(r.epss) })).sort((a, b) => a.ly - b.ly)
  for (let i = 1; i < labels.length; i++) labels[i].ly = Math.max(labels[i].ly, labels[i - 1].ly + 15)
  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: 'auto', display: 'block' }} role="img" aria-label="Exploit likelihood (EPSS) seven days ago and now">
      <line x1={XL} x2={XL} y1={16} y2={H - 26} stroke={GRID} /><line x1={XR} x2={XR} y1={16} y2={H - 26} stroke={GRID} />
      <text x={XL} y={H - 8} textAnchor="middle" fontSize={11.5} fill={MUTED}>7 days ago</text>
      <text x={XR} y={H - 8} textAnchor="middle" fontSize={11.5} fill={MUTED}>now</text>
      {top.map(r => {
        const c = r.surge ? SERIES[0] : NEUTRAL
        return (
          <g key={r.cve} style={{ cursor: 'pointer' }} onClick={() => onPick(r.cve)}>
            <line x1={XL} x2={XR} y1={y(r.epss_7d)} y2={y(r.epss)} stroke={c} strokeWidth={2} />
            <circle cx={XL} cy={y(r.epss_7d)} r={4} fill={c} /><circle cx={XR} cy={y(r.epss)} r={5} fill={c} stroke={SURFACE} strokeWidth={1.5} />
            <title>{`${r.cve} · ${r.vendor || ''} ${r.product || ''}: ${pct(r.epss_7d)} → ${pct(r.epss)}${r.exposed_orgs ? ` · ${r.exposed_orgs} exposed orgs` : ''}`}</title>
          </g>)
      })}
      {labels.map(({ r, ly }) => (
        <text key={r.cve} x={XR + 12} y={ly + 4} fontSize={11.5} fill={INK2} style={{ cursor: 'pointer' }} onClick={() => onPick(r.cve)}>
          {r.cve} · {pct(r.epss)}{r.exposed_orgs ? ` · ${r.exposed_orgs} org${r.exposed_orgs === 1 ? '' : 's'}` : ''}
        </text>))}
    </svg>
  )
}

/* ------------------------------------------------------------------ page */
export default function Speed() {
  const { range } = useRange()
  const nav = useNavigate()
  const loc = useLocation()
  const { data } = useApi<any>(`/speed?days=${range}`, 300)
  const [dueDay, setDueDay] = useState<string | null>(null)
  const [allPath, setAllPath] = useState(false)
  const [allDue, setAllDue] = useState(false)
  // deep links from other pages (/speed#race, #spread, #path, #due, #early) open the right chapter
  useEffect(() => {
    if (!data || !loc.hash) return
    const t = setTimeout(() => go(loc.hash.slice(1)), 80)
    return () => clearTimeout(t)
  }, [!!data, loc.hash]) // eslint-disable-line react-hooks/exhaustive-deps
  if (!data) return <div className="muted">Timing the threat picture…</div>

  const w = data.win, p = data.prev, sla = data.sla
  const b30 = data.beaten.find((b: any) => b.days === sla.high)
  const spreadingNow = data.spreading.filter((s: any) => s.spreading)
  const fastest3 = Math.min(...spreadingNow.map((s: any) => s.hours_to_3 ?? Infinity))
  const bn = (k: string) => data.board[k]?.n || 0
  const act72 = bn('overdue') + bn('72h')
  const sum = (c: any) => (c.critical || 0) + (c.high || 0) + (c.medium || 0) + (c.low || 0)
  const due14 = data.calendar.slice(1).reduce((a: number, c: any) => a + sum(c), 0)
  const overdue = sum(data.calendar[0] || {})
  const since = data.coverage?.collected_since
  const shallow = since && (Date.now() - Date.parse(since)) / 864e5 < Number(range)
  const cal = dueDays(data.calendar)
  const now = Date.now()
  const dueRows = data.clocks.rows.filter((r: any) => (dueDay ? (dueDay === 'overdue' ? r.overdue : r.act_by.slice(0, 10) === dueDay) : Date.parse(r.act_by) - now <= 3 * 864e5))
  const maxReach = Math.max(1, ...data.threats.map((t: any) => t.orgs))
  const linkCount: Record<string, number> = {}
  for (const r of data.in_path) for (const t of r.threats) linkCount[t.link] = (linkCount[t.link] || 0) + 1
  const linkRows = Object.entries(linkCount).sort((a, b) => b[1] - a[1])
  const trend = w.median != null && p.median != null ? w.median - p.median : null
  const pickCve = (cve: string) => nav(`/exposure?cve=${encodeURIComponent(cve)}`)

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">Speed & spread · last {range} days</div>
          <h2>Attackers move in days. Who is in the path — and what is due, by when</h2>
          <p>Four questions, in order: how fast are vulnerabilities being exploited compared with your deadline rules; which incidents are spreading;
            which monitored organisations they reach; and what each of them must do by when. Every number follows the 7 / 30 / 90-day selector unless marked “now”.</p>
          {shallow && <p className="muted" style={{ fontSize: 12.5 }}>AEGIS began collecting on {day(since)}. Windows reaching further back show what the sources themselves published for that period.</p>}
        </div>
      </div>

      <StoryStrip items={[
        { label: '1 · The race', value: w.median != null ? `${w.median} days` : '—', title: 'median from disclosure to exploitation', onClick: () => go('race'),
          sub: `${pc(w.share_7d)} exploited within a week, ${w.zero_day} zero-day${w.zero_day === 1 ? '' : 's'}${b30?.share != null ? ` · ${pc(b30.share)} before a ${sla.high}-day deadline would end` : ''}` },
        { label: '2 · Spreading', value: spreadingNow.length, title: `incident${spreadingNow.length === 1 ? '' : 's'} spreading`, onClick: () => go('spread'),
          sub: Number.isFinite(fastest3) ? `fastest: third publisher after ${Math.round(fastest3)} hours` : '3+ publishers within 72 hours' },
        { label: '3 · In the path', value: data.in_path_total, title: `organisation${data.in_path_total === 1 ? '' : 's'} in the path`, onClick: () => go('path'),
          sub: `reached by a spreading or fast-exploited incident · ${act72} must act within 72 hours` },
        { label: '4 · Due', value: due14, title: 'actions due in the next 14 days', onClick: () => go('due'), sub: overdue ? `${overdue} already overdue` : 'none overdue' },
      ]} />

      <Chapter id="race" n={1} title="The race: how fast attackers exploit, against your deadline rules"
        so={<>{data.kev_window} CVEs were newly confirmed exploited in the last {range} days (previous {range} days: {data.kev_prev}).
          {w.window !== Number(range) && <> Time to exploit uses {w.window} days because the window holds fewer than 10.</>}
          {trend != null && <> The median is {Math.abs(trend) < 0.5 ? 'unchanged' : trend < 0 ? `${Math.abs(trend)} days faster` : `${trend} days slower`} than the previous period.</>}</>}>
        <div className="grid g-main-side">
          <Card title="Each dot is a newly exploited CVE" sub={`placed by days from disclosure to confirmed exploitation · last ${w.window} days · blue = runs at a monitored organisation · click a dot for its card`}>
            <RaceChart race={data.race} sla={sla} onPick={r => pickCve(r.cve)} />
          </Card>
          <Card title="How often attackers beat each deadline" sub="share of these CVEs exploited within the deadline's length of their disclosure — a clock that starts at disclosure would already have run out">
            <div className="stack" style={{ gap: 14 }}>
              {data.beaten.map((b: any) => (
                <div key={b.label}>
                  <div className="row" style={{ justifyContent: 'space-between', fontSize: 13 }}><span>{b.label}</span><b>{pc(b.share)}</b></div>
                  <div style={{ height: 8, background: 'var(--hair)', borderRadius: 4, margin: '4px 0 3px' }}><div style={{ width: `${(b.share || 0) * 100}%`, height: '100%', background: SERIES[0], borderRadius: 4 }} /></div>
                  <div className="muted" style={{ fontSize: 11.5 }}>{b.n} of {b.of} exploited within {b.days < 1 ? `${Math.round(b.days * 24)} hours` : `${b.days} day${b.days === 1 ? '' : 's'}`} of disclosure</div>
                </div>))}
              <div className="muted" style={{ fontSize: 11.5 }}>Industry context: Google/Mandiant put the average time to exploit at −7 days in 2025 — exploitation before a patch is public.</div>
            </div>
          </Card>
        </div>
        <div className="grid g2" style={{ marginTop: 14 }}>
          <Card title="Is it getting faster?" sub="median days from disclosure to exploitation, by quarter of KEV addition · 12 months · lower = faster">
            {data.exploit.y12.by_quarter.length ? <Columns data={data.exploit.y12.by_quarter} x="quarter" y="median" height={200} /> : <Empty>—</Empty>}
          </Card>
          <Card title="Fastest-exploited vendors" sub="median days from disclosure to exploitation, and the share of the vendor's exploited CVEs hit within 7 days · 12 months · vendors with 3+ exploited CVEs">
            <div className="stack" style={{ gap: 7 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '110px 76px minmax(0,1fr) 40px', gap: 10, fontSize: 11.5, color: 'var(--muted)' }}>
                <span>Vendor</span><span>Median</span><span>Exploited within 7 days</span><span />
              </div>
              {data.exploit.vendors.slice(0, 10).map((v: any) => (
                <div key={v.vendor} style={{ display: 'grid', gridTemplateColumns: '110px 76px minmax(0,1fr) 40px', gap: 10, alignItems: 'center', fontSize: 12.5 }}>
                  <b className="trunc">{v.vendor}</b>
                  <span>{v.median <= 0 ? 'zero-day' : `${v.median} day${v.median === 1 ? '' : 's'}`}</span>
                  <div style={{ height: 10, background: 'var(--hair)', borderRadius: 5 }}><div style={{ width: `${(v.fast / Math.max(1, v.n)) * 100}%`, height: '100%', background: SERIES[0], borderRadius: 5 }} /></div>
                  <span className="muted" style={{ textAlign: 'right' }}>{v.fast}/{v.n}</span>
                </div>))}
            </div>
          </Card>
        </div>
      </Chapter>

      <Chapter id="spread" n={2} title="What is spreading"
        so={`${spreadingNow.length} incident${spreadingNow.length === 1 ? ' was' : 's were'} picked up by 3 or more independent publishers within 72 hours in the last ${range} days — the signal that exploitation or a leak is becoming widely known and copied.`}>
        <Card>
          {!data.spreading.length ? <Empty>No incident has been picked up by more than one publisher in this window.</Empty>
            : <SpreadLanes rows={data.spreading.slice(0, 10)} onOpen={id => nav(`/incidents/${id}`)} />}
        </Card>
      </Chapter>

      <Chapter id="path" n={3} title="Who is in the path"
        so={`${data.in_path_total} monitored organisations are reached by a spreading or fast-exploited incident — as named victim, corporate group, provider user, named customer, or because they run the product. ${act72} must act within 72 hours.`}>
        <div className={linkRows.length > 1 ? 'grid g-main-side' : 'grid'} style={{ marginBottom: 14 }}>
          <Card title="Fast-moving incidents, by how many organisations they reach"
            sub={`last ${range} days${linkRows.length === 1 ? ` · every organisation here is linked because it ${LINK[linkRows[0][0]] || linkRows[0][0]}` : ''} · click to see every link and its evidence`}>
            {!data.threats.length ? <Empty>No fast-moving incident reaches a monitored organisation in this window.</Empty> : (
              <div className="stack" style={{ gap: 8 }}>{data.threats.map((t: any) => (
                <div key={t.id} className="clickable" onClick={() => nav(`/incidents/${t.id}`)} style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 2fr) minmax(0, 2fr) 44px', gap: 10, alignItems: 'center' }}>
                  <div style={{ minWidth: 0 }}>
                    <div className="row" style={{ gap: 6, minWidth: 0 }}><Sev level={t.severity} compact /><span className="trunc" style={{ fontSize: 12.5 }} title={t.title}>{t.title}</span></div>
                    <div className="muted" style={{ fontSize: 11.5, marginLeft: 22 }}>{t.why}</div>
                  </div>
                  <div style={{ height: 12, background: 'var(--hair)', borderRadius: 6 }}><div style={{ width: `${(t.orgs / maxReach) * 100}%`, height: '100%', background: SERIES[0], borderRadius: 6 }} /></div>
                  <b style={{ textAlign: 'right' }}>{t.orgs}</b>
                </div>))}</div>)}
          </Card>
          {linkRows.length > 1 && (
            <Card title="What reaches them" sub="how each in-path organisation is linked">
              <div className="stack" style={{ gap: 10 }}>{linkRows.map(([k, n]) => (
                <div key={k}><div className="row" style={{ justifyContent: 'space-between', fontSize: 12.5 }}><span>{LINK[k] || k}</span><b>{n}</b></div>
                  <div style={{ height: 8, background: 'var(--hair)', borderRadius: 4, marginTop: 3 }}><div style={{ width: `${(n / Math.max(1, linkRows[0][1])) * 100}%`, height: '100%', background: SERIES[1], borderRadius: 4 }} /></div></div>))}
                <div className="muted" style={{ fontSize: 11.5 }}>Organisation–incident links among the organisations in the path.</div>
              </div>
            </Card>)}
        </div>
        <Card title="Every organisation with an open deadline, by when it must act" sub="now · ⚡ = in the path of a fast-moving incident">
          <DeadlineBoard board={data.board} onOrg={id => nav(`/orgs/${id}`)} />
        </Card>
      </Chapter>

      <Chapter id="due" n={4} title="What is due, and when"
        so={<>Every Critical, High and Medium finding carries an act-by date from one named deadline rule. {overdue ? `${overdue} are overdue; ` : ''}{due14} fall due in the next 14 days. Click a day to list them.</>}>
        <div className="grid g-main-side">
          <Card title="Actions due per day" sub="now · stacked by level · click a bar to list that day's actions">
            <StackedBars data={cal} x="label" keys={['critical', 'high', 'medium']} names={['Critical', 'High', 'Medium']}
              colors={[SEV_COLOR.critical, SEV_COLOR.high, SEV_COLOR.medium]} height={250} interval={0}
              onClick={(row: any) => setDueDay(dueDay === row.day ? null : row.day)} />
            <div className="row wrap" style={{ gap: 12, fontSize: 12 }}>
              {(['critical', 'high', 'medium'] as const).map(l => <Sev key={l} level={l} />)}
              {Object.entries(data.later).map(([k, n]: any) => <span key={k} className="pill">{k}: {n}</span>)}
            </div>
          </Card>
          <Card title="Which rule sets each clock" sub="now · hover a clock in the list for its rule">
            <div className="stack" style={{ gap: 8 }}>{Object.entries(data.clocks.by_rule).sort((a: any, b: any) => b[1] - a[1]).map(([r, n]: any) => (
              <div key={r} className="row" style={{ justifyContent: 'space-between', fontSize: 12.5 }}><span className="mono">{r}</span><b>{n}</b></div>))}
              <div className="muted" style={{ fontSize: 11.5 }}>DL-72H: exploited edge products and live phishing · DL-CISA: the CISA due date · DL-7D-EXPLOITED: exploited product seen, version unconfirmed · DL-7D / 30D / 90D: by level. Full definitions under Sources → Rating rules.</div>
            </div>
          </Card>
        </div>
        <Card title={dueDay ? `Due ${dueDay === 'overdue' ? '— overdue' : `on ${day(dueDay)}`}` : 'Due within the next 72 hours'} sub="click a row to open the organisation"
          right={<span className="row" style={{ gap: 12 }}>
            {dueDay && <a className="srclink" onClick={() => setDueDay(null)}>Back to the next 72 hours</a>}
            {dueRows.length > 12 && <button className="btn" onClick={() => setAllDue(a => !a)}>{allDue ? 'Show 12' : `Show all ${dueRows.length}`}</button>}
          </span>}>
          <Table rows={allDue ? dueRows : dueRows.slice(0, 12)} max={200} onRow={(f: any) => nav(`/orgs/${f.org_id}`)} empty="Nothing due in this period." cols={[
            { key: 'act_by', label: 'Clock', render: (f: any) => <ActBy ts={f.act_by} rule={f.deadline_rule} />, sort: (f: any) => f.act_by },
            { key: 'severity', label: 'Level', render: (f: any) => <Sev level={f.severity} rule={f.rule_id} />, sort: (f: any) => RANKV[f.severity] },
            { key: 'org', label: 'Organisation', render: (f: any) => <b>{f.org}</b> },
            { key: 'title', label: 'What to act on', render: (f: any) => <span className="clamp2">{f.title}</span> },
            { key: 'exploited_since', label: 'Exploited since', render: (f: any) => (f.exploited_since ? day(f.exploited_since) : '') }]} />
        </Card>
      </Chapter>

      <Chapter id="early" n={5} title="Early warnings — before exploitation is confirmed"
        so="Signals that usually come before the clocks above start: exploit likelihood rising, lookalike domains going live, extortion groups speeding up.">
        <div className="grid g3">
          <Card title="Exploit likelihood rising" sub="FIRST EPSS, 7 days ago → now · not yet in CISA KEV · blue = surge (rule VUL-EPSS-SURGE) · click for the CVE card">
            <Slope rows={data.surges} onPick={pickCve} />
          </Card>
          <Card title="Lookalikes go live fast" sub={`newly registered brand + lure domains · last ${range} days`}>
            {data.lookalike_speed.checked ? (
              <div className="clickable" onClick={() => nav('/impersonation')}>
                <div style={{ fontSize: 30, fontWeight: 700 }}>{data.lookalike_speed.live_within_3d}<span className="muted" style={{ fontSize: 16, fontWeight: 500 }}> of {data.lookalike_speed.checked}</span></div>
                <div style={{ fontSize: 13 }}>already resolving within 3 days of registration</div>
                <div style={{ height: 10, background: 'var(--hair)', borderRadius: 5, margin: '10px 0 6px' }}><div style={{ width: `${(data.lookalike_speed.live_within_3d / data.lookalike_speed.checked) * 100}%`, height: '100%', background: SERIES[0], borderRadius: 5 }} /></div>
                <div className="muted" style={{ fontSize: 12 }}>Phishing set-up takes days, which is why live lookalikes get the 72-hour clock. Open Impersonation & IOCs →</div>
              </div>) : <Empty>No lookalike registered in this window{data.coverage?.lookalikes_since ? ` (collection began ${day(data.coverage.lookalikes_since)})` : ''}.</Empty>}
          </Card>
          <Card title="Extortion-group tempo" sub="leak-site victims, last 7 days vs the prior 4-week weekly average">
            {!data.tempo.mature && <div className="muted" style={{ fontSize: 12, marginBottom: 8 }}>Baseline maturing: {data.tempo.history_days} of 28 days collected — no surge is asserted until then.</div>}
            {!data.tempo.groups.length ? <Empty>No leak-site listings in the last 7 days.</Empty> : (
              <div className="stack" style={{ gap: 7 }}>{data.tempo.groups.slice(0, 7).map((g: any) => {
                const mx = Math.max(...data.tempo.groups.map((x: any) => x.last7))
                return (
                  <div key={g.group} className="clickable" onClick={() => nav(`/adversaries/rw-${String(g.group).toLowerCase()}`)} style={{ display: 'grid', gridTemplateColumns: '96px minmax(0,1fr) 28px', gap: 8, alignItems: 'center', fontSize: 12.5 }}>
                    <span className="trunc">{g.group}</span>
                    <div style={{ height: 10, background: 'var(--hair)', borderRadius: 5, position: 'relative' }}>
                      <div style={{ width: `${(g.last7 / mx) * 100}%`, height: '100%', background: SERIES[2], borderRadius: 5 }} />
                      {data.tempo.mature && <div title="weekly baseline" style={{ position: 'absolute', left: `${Math.min(100, (g.baseline / mx) * 100)}%`, top: -3, bottom: -3, borderLeft: `2px solid ${INK2}` }} />}
                    </div>
                    <b style={{ textAlign: 'right' }}>{g.last7}</b>
                  </div>)
              })}</div>)}
          </Card>
        </div>
      </Chapter>

      <details style={{ marginTop: 10 }}>
        <summary className="clickable" style={{ fontWeight: 600, padding: '8px 0' }}>Reference lists — every organisation in the path, every fast-exploited CVE</summary>
        <div className="stack" style={{ gap: 14, marginTop: 8 }}>
          <Card title="Organisations in the path of fast-moving incidents" sub={`last ${range} days · click to open`}
            right={data.in_path.length > 15 ? <button className="btn" onClick={() => setAllPath(a => !a)}>{allPath ? 'Show top 15' : `Show all ${data.in_path.length}`}</button> : undefined}>
            <Table rows={allPath ? data.in_path : data.in_path.slice(0, 15)} max={80} onRow={(r: any) => nav(`/orgs/${r.org_id}`)} empty="None in this window." cols={[
              { key: 'worst', label: 'Level', render: (r: any) => <Sev level={r.worst} />, sort: (r: any) => RANKV[r.worst] },
              { key: 'name', label: 'Organisation', render: (r: any) => <b>{r.name}</b> },
              { key: 'threats', label: 'Fast-moving incidents reaching it', render: (r: any) => (
                <div className="stack" style={{ gap: 3 }}>{r.threats.slice(0, 3).map((t: any) => (
                  <div key={t.id + t.link} style={{ fontSize: 12.5 }}>{t.title}<span className="muted"> · {LINK[t.link] || t.link}{t.why ? ` · ${t.why}` : ''}</span></div>))}
                  {r.n > 3 && <span className="muted" style={{ fontSize: 12 }}>+{r.n - 3} more</span>}</div>), sort: (r: any) => r.n },
              { key: 'act_72h', label: '72h actions', num: true, render: (r: any) => r.act_72h || '' },
              { key: 'next_act_by', label: 'Next act-by', render: (r: any) => <ActBy ts={r.next_act_by} />, sort: (r: any) => r.next_act_by || '9' }]} />
          </Card>
          <Card title={`Exploited within a week of disclosure — last ${range} days`} sub="CISA KEV additions with a disclosure-to-exploitation gap of 7 days or less">
            <Table rows={data.fast} max={40} empty="None in this window." cols={[
              { key: 'cve', label: 'CVE', render: (v: any) => <a className="clickable" onClick={() => pickCve(v.cve)}>{v.cve}</a> },
              { key: 'vendor', label: 'Product', render: (v: any) => <><b>{v.vendor}</b> {v.product}</> },
              { key: 'lag', label: 'Exploited', render: (v: any) => <span className="pill">{v.lag <= 0 ? 'zero-day' : `${v.lag}d after disclosure`}</span>, sort: (v: any) => v.lag },
              { key: 'kev_due', label: 'CISA due', render: (v: any) => day(v.kev_due) },
              { key: 'orgs', label: 'Exposed monitored organisations', render: (v: any) => (v.orgs || []).map((o: any) => o.name).join(', ') || <span className="muted">none</span>, sort: (v: any) => (v.orgs || []).length },
              { key: 'nvd', label: '', render: (v: any) => <SourceLink url={`https://nvd.nist.gov/vuln/detail/${v.cve}`} label="NVD" /> }]} />
          </Card>
          <Card title="Rising exploit likelihood — full list" sub="not yet exploited · EPSS week on week">
            <Table rows={data.surges} max={40} empty="None." cols={[
              { key: 'cve', label: 'CVE', render: (v: any) => <a className="clickable" onClick={() => pickCve(v.cve)}>{v.cve}</a> },
              { key: 'vendor', label: 'Product', render: (v: any) => `${v.vendor || ''} ${v.product || ''}` },
              { key: 'epss', label: 'EPSS now', num: true, render: (v: any) => pct(v.epss) },
              { key: 'epss_7d', label: '7 days ago', num: true, render: (v: any) => pct(v.epss_7d) },
              { key: 'exposed_orgs', label: 'Exposed orgs', num: true }]} />
          </Card>
          <div className="muted" style={{ fontSize: 12 }}>Last refreshed <When ts={new Date().toISOString()} /></div>
        </div>
      </details>

      <PageSources cats={['Vulnerabilities', 'News', 'Government', 'Research', 'Attack surface', 'Dark web']}
        note="Time to exploit = CVE publication (NVD / CVE record) → CISA KEV addition. Spread = independent publishers of the same incident. Deadlines = the named DL-* rules on Sources & method." />
    </div>
  )
}
