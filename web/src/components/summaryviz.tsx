import { Fragment, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { Card, Empty, Sev } from './ui'
import { RcTip } from './charts'
import { SEV_COLOR, SERIES, NEUTRAL, INK2, MUTED, GRID, CURSOR, SURFACE, rcAxis } from '../lib/chartTheme'

/* ------------------------------------------------------------------ the race: attacker speed vs deadline rules */
const RW = 1000, RH = 240, X0 = 120, X1 = 980, ZB: [number, number] = [34, 96], CY = 112, YMIN = 34, YMAX = 190, LMAX = 730
const TICKS = [1, 3, 7, 14, 30, 90, 180, 365, 730]
const xOf = (lag: number) => (lag <= 1 ? X0 : X0 + (Math.log(Math.min(lag, LMAX)) / Math.log(LMAX)) * (X1 - X0))
const tickLabel = (t: number) => (t < 30 ? `${t}d` : t === 30 ? '1 mo' : t === 90 ? '3 mo' : t === 180 ? '6 mo' : t === 365 ? '1 yr' : '2 yr+')

function swarm<T extends { x: number; r: number }>(items: T[]): (T & { y: number })[] {
  // simple beeswarm: keep each dot at its x, stack vertically around the centre line, step right only if a column is full
  const placed: { x: number; y: number; r: number }[] = []
  return items.map(it => {
    let x = it.x
    for (let attempt = 0; attempt < 8; attempt++) {
      for (let k = 0; k < 40; k++) {
        const y = CY + Math.ceil(k / 2) * (it.r * 2 + 1) * (k % 2 ? 1 : -1)
        if (y < YMIN || y > YMAX) continue
        if (placed.every(p => (p.x - x) ** 2 + (p.y - y) ** 2 >= (p.r + it.r + 1) ** 2)) { placed.push({ x, y, r: it.r }); return { ...it, x, y } }
      }
      x += it.r * 2 + 1
    }
    placed.push({ x, y: CY, r: it.r })
    return { ...it, x, y: CY }
  })
}

/** Each dot = a CVE newly confirmed exploited, placed by days from disclosure to exploitation (log scale); dashed lines = deadline rules. */
export function RaceChart({ race, sla, onPick, compact }: { race: any[]; sla: any; onPick: (r: any) => void; compact?: boolean }) {
  const [hov, setHov] = useState<any>(null)
  const dots = useMemo(() => swarm(race.map(r => ({ ...r, x: r.lag <= 0 ? ZB[0] + 8 : xOf(r.lag), r: r.orgs > 0 ? 6.5 : 4.5 }))
    .sort((a, b) => a.x - b.x || b.r - a.r)), [race])
  const marks = [{ d: sla.edge_hours / 24, label: `${sla.edge_hours}h` }, { d: sla.critical, label: `${sla.critical}-day` }, { d: sla.high, label: `${sla.high}-day` }, { d: sla.medium, label: `${sla.medium}-day` }]
  if (!race.length) return <Empty>No CVE was newly added to CISA KEV in this window.</Empty>
  return (
    <div style={{ position: 'relative' }}>
      <svg viewBox={`0 0 ${RW} ${RH}`} style={{ width: '100%', height: 'auto', display: 'block' }} role="img"
        aria-label="Each dot is a CVE newly confirmed exploited, placed by days from disclosure to exploitation; dashed lines are the deadline rules">
        <rect x={ZB[0] - 8} y={YMIN - 12} width={ZB[1] - ZB[0] + 16} height={YMAX - YMIN + 24} rx={8} fill={MUTED} opacity={0.1} />
        <rect x={X0} y={YMIN - 12} width={xOf(sla.high) - X0} height={YMAX - YMIN + 24} fill={SERIES[0]} opacity={0.06} />
        <line x1={X0} x2={X1} y1={YMAX + 16} y2={YMAX + 16} stroke={GRID} />
        <text x={(ZB[0] + ZB[1]) / 2} y={RH - 12} textAnchor="middle" fontSize={12} fill={MUTED}>zero-day</text>
        {TICKS.map(t => (
          <g key={t}>
            <line x1={xOf(t)} x2={xOf(t)} y1={YMAX + 16} y2={YMAX + 22} stroke={MUTED} />
            <text x={xOf(t)} y={RH - 12} textAnchor="middle" fontSize={12} fill={MUTED}>{tickLabel(t)}</text>
          </g>))}
        {marks.map(m => (
          <g key={m.label}>
            <line x1={xOf(m.d)} x2={xOf(m.d)} y1={20} y2={YMAX + 16} stroke={INK2} strokeDasharray="4 4" opacity={0.75} />
            <text x={xOf(m.d)} y={13} textAnchor="middle" fontSize={12} fontWeight={600} fill={INK2}>{m.label}</text>
          </g>))}
        {dots.map(d => (
          <circle key={d.cve} cx={d.x} cy={d.y} r={d.r} fill={d.orgs > 0 ? SERIES[0] : NEUTRAL} stroke={SURFACE} strokeWidth={1.5}
            style={{ cursor: 'pointer' }} onMouseEnter={() => setHov(d)} onMouseLeave={() => setHov(null)} onClick={() => onPick(d)} />))}
      </svg>
      {hov && (
        <div className="tip" style={{ position: 'absolute', left: `${Math.min(68, (hov.x / RW) * 100)}%`, top: `${(hov.y / RH) * 100}%`, transform: 'translate(14px, -50%)', pointerEvents: 'none' }}>
          <strong>{hov.cve}</strong> · {hov.vendor} {hov.product}
          <div>{hov.lag <= 0 ? 'Exploited at or before disclosure (zero-day)' : `Exploited ${hov.lag} day${hov.lag === 1 ? '' : 's'} after disclosure`}{hov.ransomware ? ' · used by ransomware' : ''}</div>
          <div>{hov.orgs ? `Runs at ${hov.orgs} monitored organisation${hov.orgs === 1 ? '' : 's'}` : 'Not seen at a monitored organisation'}</div>
        </div>)}
      {!compact && (
        <div className="row wrap" style={{ gap: 16, fontSize: 12, marginTop: 6 }}>
          <span className="row" style={{ gap: 6 }}><svg width="14" height="14"><circle cx="7" cy="7" r="6" fill={SERIES[0]} /></svg>runs at a monitored organisation</span>
          <span className="row" style={{ gap: 6 }}><svg width="12" height="12"><circle cx="6" cy="6" r="4.5" fill={NEUTRAL} /></svg>not seen at a monitored organisation</span>
          <span className="muted">x = days from disclosure (CVE published) to confirmed exploitation (added to CISA KEV), log scale · dashed = deadline rules · shaded = exploited before a {sla.high}-day deadline</span>
        </div>)}
    </div>
  )
}

/* ------------------------------------------------------------------ stacked columns (per day, by level) */
export function StackedBars({ data, x, keys, names, colors, height = 220, onClick, interval = 'preserveStartEnd', grouped = false }: {
  data: any[]; x: string; keys: string[]; names?: string[]; colors: string[]; height?: number; onClick?: (row: any) => void; interval?: number | 'preserveStartEnd'
  grouped?: boolean  // side-by-side bars instead of a stack (e.g. raised vs closed)
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }} barCategoryGap="18%"
        onClick={(s: any) => { const p = s?.activePayload?.[0]?.payload; if (p && onClick) onClick(p) }}>
        <CartesianGrid vertical={false} stroke={GRID} />
        <XAxis dataKey={x} {...rcAxis} interval={interval} tick={{ ...rcAxis.tick, fontSize: 10.5 }} />
        <YAxis {...rcAxis} allowDecimals={false} width={30} />
        <Tooltip content={<RcTip />} cursor={{ fill: CURSOR }} />
        {keys.map((k, i) => <Bar key={k} dataKey={k} name={names?.[i] || k} stackId={grouped ? undefined : 'a'} fill={colors[i]} stroke={SURFACE} strokeWidth={1}
          radius={grouped ? [3, 3, 0, 0] : undefined} cursor={onClick ? 'pointer' : undefined} />)}
      </BarChart>
    </ResponsiveContainer>
  )
}

/** The act-by calendar with readable day labels: Overdue, Today, then weekday + date. */
export const dueDays = (calendar: any[]) => calendar.map((c: any, i: number) => ({
  ...c, label: c.day === 'overdue' ? 'Overdue' : i === 1 ? 'Today' : new Date(`${c.day}T00:00:00`).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric' }),
}))

/* ------------------------------------------------------------------ Situation: speed, from exploitation to action */
export function SpeedSummary({ sp, range }: { sp: any; range: string }) {
  const nav = useNavigate()
  const w = sp.win
  const atOrgs = sp.race.filter((r: any) => r.orgs > 0).length
  const act72 = (sp.board?.overdue?.n || 0) + (sp.board?.['72h']?.n || 0)
  const spreading = sp.spreading.filter((s: any) => s.spreading)
  const fastest = Math.min(...spreading.map((s: any) => s.hours_to_3 ?? Infinity))
  const stages = [
    { n: sp.kev_window, t: 'CVEs newly exploited', s: `last ${range} days · previous ${range} days: ${sp.kev_prev}`, to: 'race' },
    { n: w.share_7d != null ? `${Math.round(w.share_7d * 100)}%` : '—', t: 'exploited within 7 days of disclosure', s: `median ${w.median ?? '—'} days from disclosure${w.window !== Number(range) ? ` (${w.window}-day basis)` : ''}`, to: 'race' },
    { n: atOrgs, t: `of them run at monitored organisations`, s: 'seen on their internet-facing hosts or products', to: 'race' },
    { n: sp.in_path_total, t: 'organisations in the path', s: `reached by a spreading or fast-exploited incident · ${spreading.length} spreading`, to: 'path' },
    { n: act72, t: 'must act within 72 hours', s: `${sp.board?.overdue?.n || 0} overdue · by deadline rule`, to: 'due' },
  ]
  return (
    <Card title="Speed: from exploitation to action" sub={`how fast attackers moved in the last ${range} days, and what it means for monitored organisations now · click any step`}
      right={<a className="srclink" onClick={() => nav('/speed')}>Speed & spread <ChevronRight size={12} /></a>}>
      <div className="row" style={{ gap: 4, alignItems: 'stretch', flexWrap: 'wrap', marginBottom: 16 }}>
        {stages.map((st, i) => (
          <Fragment key={i}>
            <div className="clickable" onClick={() => nav(`/speed#${st.to}`)} title="open this step on Speed & spread"
              style={{ flex: '1 1 150px', background: 'var(--raised)', border: '1px solid var(--hair)', borderTop: `3px solid ${i === stages.length - 1 && act72 ? SEV_COLOR.high : SERIES[0]}`, borderRadius: 10, padding: '10px 12px' }}>
              <div style={{ fontSize: 26, fontWeight: 700, lineHeight: 1.1 }}>{st.n}</div>
              <div style={{ fontSize: 12.5, fontWeight: 600, marginTop: 3 }}>{st.t}</div>
              <div className="muted" style={{ fontSize: 11.5, marginTop: 3 }}>{st.s}</div>
            </div>
            {i < stages.length - 1 && <div aria-hidden style={{ display: 'grid', placeItems: 'center', color: 'var(--muted)', width: 16 }}><ChevronRight size={16} /></div>}
          </Fragment>))}
      </div>
      <div className="grid g-main-side" style={{ gap: 16 }}>
        <div className="clickable" onClick={e => { if ((e.target as Element).tagName !== 'circle') nav('/speed#race') }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>
            Each dot is a CVE newly exploited in the last {w.window} days, placed by days from disclosure to exploitation · dashed lines = your deadline rules · blue = runs at a monitored organisation
          </div>
          <RaceChart race={sp.race} sla={sp.sla} compact onPick={r => nav(`/exposure?cve=${r.cve}`)} />
        </div>
        <div>
          <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>
            Actions due per day (now){Number.isFinite(fastest) ? ` · fastest-spreading incident reached 3 publishers in ${Math.round(fastest)}h` : ''}
          </div>
          <StackedBars data={dueDays(sp.calendar)} x="label" keys={['critical', 'high', 'medium']} names={['Critical', 'High', 'Medium']}
            colors={[SEV_COLOR.critical, SEV_COLOR.high, SEV_COLOR.medium]} height={190} onClick={() => nav('/speed#due')} />
          <div className="row wrap" style={{ gap: 10, fontSize: 12 }}>{(['critical', 'high', 'medium'] as const).map(l => <Sev key={l} level={l} />)}</div>
        </div>
      </div>
    </Card>
  )
}
