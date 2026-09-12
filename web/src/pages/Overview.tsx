import { Fragment, useMemo, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowRight, Search } from 'lucide-react'
import { ResponsiveHeatMap } from '@nivo/heatmap'
import { useApi, qs } from '../lib/api'
import { useRange } from '../App'
import { Card, Sev, Empty, When, PageSources, SectionLabel } from '../components/ui'
import { OrgBrief } from '../components/brief'
import WorldMap from '../components/WorldMap'
import { StackedBars, dueDays } from '../components/summaryviz'
import { FixPipeline } from '../components/fixes'
import { SEV_COLOR, SERIES, BLUE_RAMP, EMPTY, SURFACE, nivoTheme, onFill } from '../lib/chartTheme'
import { compact, countryName, day } from '../lib/format'

const LEVEL_LABEL: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low only', clear: 'No findings', queued: 'Scan queued' }
const RANKL: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, clear: 4, queued: 5 }
const cellColor = (l: string) => SEV_COLOR[l] || (l === 'clear' ? 'var(--hair-2)' : 'transparent')
const INDIRECT = () => SERIES[4] || SERIES[1]
const go = (id: string) => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })

/* ---- the whole watchlist as one picture ---- */
function Watchlist({ grid, onOpen }: { grid: any[]; onOpen: (id: string) => void }) {
  const [hov, setHov] = useState<any>(null)
  const rows = useMemo(() => {
    const by: Record<string, any[]> = {}
    for (const g of grid) (by[g.sector] ||= []).push(g)
    return Object.entries(by).map(([s, gs]) => [s, gs.sort((a, b) => RANKL[a.level] - RANKL[b.level] || a.name.localeCompare(b.name))] as [string, any[]])
      .sort((a, b) => (a[0] === 'Unknown' ? 1 : b[0] === 'Unknown' ? -1 : b[1].length - a[1].length))
  }, [grid])
  return (
    <div>
      <div className="stack" style={{ gap: 5 }}>
        {rows.map(([s, gs]) => (
          <div key={s} className="wl-row" style={{ display: 'grid', gridTemplateColumns: '160px minmax(0,1fr) 56px', gap: 10, alignItems: 'center' }}>
            <span className="trunc" style={{ fontSize: 12.5 }} title={s}>{s}</span>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
              {gs.map(g => (
                <span key={g.id} onClick={() => onOpen(g.id)} onMouseEnter={() => setHov(g)} onMouseLeave={() => setHov(null)} title={`${g.name} · ${LEVEL_LABEL[g.level]}`}
                  role="button" aria-label={`${g.name}: ${LEVEL_LABEL[g.level]}`}
                  style={{ width: 11, height: 11, borderRadius: 2, cursor: 'pointer', background: cellColor(g.level), border: g.level === 'queued' ? '1px dashed var(--hair-2)' : `1px solid ${SURFACE}`,
                    outline: hov?.id === g.id ? '2px solid var(--accent)' : undefined }} />))}
            </div>
            <span className="muted" style={{ fontSize: 11.5, textAlign: 'right' }} title="Critical or High / total">{gs.filter(g => g.level === 'critical' || g.level === 'high').length}/{gs.length}</span>
          </div>))}
      </div>
      <div className="row wrap" style={{ gap: 10, marginTop: 10, fontSize: 12, minHeight: 22 }}>
        {(['critical', 'high', 'medium', 'low'] as const).map(l => <Sev key={l} level={l} />)}
        <span className="row" style={{ gap: 5 }}><span style={{ width: 11, height: 11, borderRadius: 2, background: 'var(--hair-2)' }} />no findings</span>
        <span className="row" style={{ gap: 5 }}><span style={{ width: 11, height: 11, borderRadius: 2, border: '1px dashed var(--hair-2)' }} />scan queued</span>
        <span className="muted" style={{ marginLeft: 'auto' }}>{hov ? <><b>{hov.name}</b> · {LEVEL_LABEL[hov.level]}</> : 'one square per organisation · click to open'}</span>
      </div>
    </div>
  )
}

function MiniBars({ rows, max, onClick }: { rows: { label: ReactNode; a: number; b?: number; title?: string; key?: string; extra?: ReactNode }[]; max?: number; onClick?: (i: number) => void }) {
  const m = max || Math.max(1, ...rows.map(r => r.a + (r.b || 0)))
  return (
    <div className="stack" style={{ gap: 6 }}>
      {rows.map((r, i) => (
        <div key={r.key || String(i)} title={r.title} className={onClick ? 'clickable' : undefined} onClick={onClick ? () => onClick(i) : undefined}
          style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.1fr) minmax(0, 1.2fr) 40px', gap: 8, alignItems: 'center', fontSize: 12.5 }}>
          <span className="trunc">{r.label}{r.extra}</span>
          <div style={{ display: 'flex', height: 8, background: 'var(--hair)', borderRadius: 4, overflow: 'hidden' }}>
            <div style={{ width: `${(r.a / m) * 100}%`, background: SERIES[0] }} />
            {!!r.b && <div style={{ width: `${(r.b / m) * 100}%`, background: INDIRECT(), borderLeft: `2px solid ${SURFACE}` }} />}
          </div>
          <b style={{ textAlign: 'right' }}>{r.a + (r.b || 0)}</b>
        </div>))}
    </div>
  )
}

const Swatch = ({ c, l }: { c: string; l: string }) => <span className="row" style={{ gap: 4 }}><span style={{ width: 9, height: 9, borderRadius: 2, background: c }} />{l}</span>

/* ---- one step of the chain: the question, the answer in a sentence, a picture, and where to go next ---- */
function Step({ n, id, q, a, to, toLabel, wide, children }: { n: number; id: string; q: string; a: ReactNode; to: string; toLabel: string; wide?: boolean; children: ReactNode }) {
  const nav = useNavigate()
  return (
    <section id={id} className={`card ${wide ? 'wide' : ''}`} style={{ scrollMarginTop: 80, display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div className="row" style={{ gap: 10, alignItems: 'flex-start' }}>
        <span className="step-n">{n}</span>
        <div style={{ minWidth: 0 }}><h3 style={{ margin: 0, fontSize: 15 }}>{q}</h3><div className="ink2" style={{ fontSize: 13, marginTop: 3 }}>{a}</div></div>
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>{children}</div>
      <a className="srclink" onClick={() => nav(to)} style={{ fontSize: 12.5 }}>{toLabel} <ArrowRight size={11} /></a>
    </section>
  )
}

function OrgPicker({ d }: { d: any }) {
  const [sel, setSel] = useState<string | null>(null)
  const [q, setQ] = useState('')
  const { data: found } = useApi<any>(q.length > 1 ? `/orgs${qs({ q })}` : null, 300)
  const id = sel || d.chain.focus_org
  const quick = [...d.chain.urgent_orgs.slice(0, 8), ...d.chain.next.orgs.slice(0, 4).map((o: any) => ({ id: o.id, name: o.name, severity: o.level }))]
    .filter((o, i, a) => a.findIndex(x => x.id === o.id) === i).slice(0, 10)
  return (
    <div className="stack" style={{ gap: 12 }}>
      <div className="row wrap" style={{ gap: 6, alignItems: 'center' }}>
        <div className="search" style={{ maxWidth: 280, flex: '1 1 200px' }}><Search size={14} /><input value={q} onChange={e => setQ(e.target.value)} placeholder="any organisation…" aria-label="Find an organisation" /></div>
        {(q.length > 1 ? (found?.orgs || []).slice(0, 6).map((o: any) => ({ id: o.id, name: o.name, severity: o.level })) : quick).map((o: any) => (
          <a key={o.id} className={`pill btn ${o.id === id ? 'on' : ''}`} onClick={() => { setSel(o.id); setQ('') }}>{o.severity && <Sev level={o.severity} compact />}{o.name}</a>))}
      </div>
      {id ? <OrgBrief id={id} /> : <Empty>Pick an organisation.</Empty>}
    </div>
  )
}

/* ---- speed, classified into bands (fastest darkest), as on Speed & spread ---- */
function BandRibbon({ bands, unit, extra }: { bands: { band: string; n: number; at_orgs?: number }[]; unit: string; extra?: (b: any) => ReactNode }) {
  const tot = bands.reduce((a, b) => a + b.n, 0)
  const shade = (i: number) => BLUE_RAMP[Math.max(0, BLUE_RAMP.length - 1 - Math.round((i * (BLUE_RAMP.length - 1)) / Math.max(1, bands.length - 1)))]
  if (!tot) return <span className="muted" style={{ fontSize: 12 }}>None in this window.</span>
  return (
    <div>
      <div style={{ display: 'flex', height: 26, borderRadius: 6, overflow: 'hidden', gap: 2 }} role="img" aria-label={bands.map(b => `${b.band}: ${b.n}`).join(', ')}>
        {bands.map((b, i) => (b.n ? (
          <div key={b.band} title={`${b.band}: ${b.n} ${unit}`} style={{ flex: b.n, background: shade(i), display: 'grid', placeItems: 'center', color: onFill(shade(i)), fontSize: 11.5, fontWeight: 700, minWidth: 18 }}>{b.n}</div>) : null))}
      </div>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '4px 14px', marginTop: 8 }}>
        {bands.map((b, i) => (
          <span key={b.band} className="row" style={{ gap: 6, fontSize: 12 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: shade(i), flex: 'none' }} />{b.band}<b style={{ marginLeft: 'auto' }}>{b.n}</b>{extra?.(b)}
          </span>))}
      </div>
    </div>
  )
}

export default function Overview() {
  const { range } = useRange()
  const nav = useNavigate()
  const { data: d, isFetching } = useApi<any>(`/landing?days=${range}`, 90)
  if (!d) return <div className="muted">Assembling the live picture…</div>
  const P = d.pressures, C = d.chain
  const lc = d.level_counts || {}
  const ramp = (p: number) => BLUE_RAMP[Math.min(BLUE_RAMP.length - 1, Math.floor((p / 100) * (BLUE_RAMP.length - 1)))]
  const fourth = P.supply.fourth || []
  const since = d.coverage?.collected_since
  const shallow = since && (Date.now() - Date.parse(since)) / 864e5 < Number(range)
  const topKind = C.where.kinds[0]
  const f0 = fourth[0]
  const steps = [
    { id: 's-where', short: 'Where', v: C.where.incidents },
    { id: 's-who', short: 'Who is hit', v: d.now.critical_orgs },
    { id: 's-how', short: 'How', v: C.how.reached },
    { id: 's-conc', short: 'Shared providers', v: C.concentration.active_n },
    { id: 's-fast', short: 'How fast', v: P.exploit.median != null ? `${P.exploit.median}d` : '—' },
    { id: 's-next', short: 'Who is next', v: C.next.total },
    { id: 's-dep', short: 'Their dependencies', v: f0 ? f0.total : P.supply.provider_incidents },
    { id: 's-actors', short: 'Who is behind', v: C.actors.active },
    { id: 's-talk', short: 'Dark web & forums', v: C.discussion.forum_claims + C.discussion.leak_listings },
    { id: 's-analysts', short: 'Analysts', v: C.analysts.items },
    { id: 's-org', short: 'So what · one organisation', v: d.now.act_72h },
  ]

  return (
    <div style={{ opacity: isFetching ? 0.9 : 1, transition: 'opacity .3s' }}>
      <div className="page-head">
        <div>
          <div className="eyebrow">Situation · last {range} days</div>
          <h2>From what is happening to what each organisation must do</h2>
          <p>Eleven questions, answered in order across {compact(d.monitored)} monitored organisations: where the issues are, who is hit and how, which shared
            providers concentrate the risk, how fast it moves, who is exposed next, what those providers depend on, who is behind it, what is being discussed
            and what analysts say — ending with the risk for one organisation, what it must do, and whether fixes are being applied. Each answer links to the
            page with the evidence; hover any abbreviation for its meaning.</p>
          {shallow && <p className="muted" style={{ fontSize: 12 }}>Collection began on {day(since)}; windows reaching further back show what the sources published for that period.</p>}
        </div>
      </div>

      {/* the chain at a glance */}
      <div className="chain-strip" role="navigation" aria-label="The eleven questions">
        {steps.map((s, i) => (
          <Fragment key={s.id}>
            <a className="chain-chip" onClick={() => go(s.id)}><span className="step-n sm">{i + 1}</span>{s.short}<b>{s.v}</b></a>
            {i < steps.length - 1 && <span className="chain-arrow" aria-hidden>›</span>}
          </Fragment>))}
      </div>
      <div className="stack" style={{ gap: 4, marginBottom: 16 }}>
        {d.brief.map((b: any, i: number) => (
          <a key={i} className="clickable" onClick={() => nav(b.to)} style={{ fontSize: 13.5, color: 'var(--ink)', display: 'flex', gap: 8, alignItems: 'baseline' }}>
            <span style={{ color: 'var(--accent)', fontWeight: 700 }}>›</span><span>{b.text}</span></a>))}
      </div>

      <SectionLabel>The threat — what is happening</SectionLabel>
      <div className="chain-grid">
        <Step n={1} id="s-where" q="Where are the issues?" to="/incidents" toLabel="Incidents & impact" wide
          a={<><b>{C.where.incidents}</b> incidents in the last {range} days, <b>{C.where.critical}</b> Critical{topKind ? <> — most often {topKind.kind.toLowerCase()} ({topKind.n})</> : ''}.
            Each dot is an incident placed at the victim's country, coloured by level — scroll or use +/− to zoom, click a dot to open it.</>}>
          <div className="grid g-main-side" style={{ gap: 16, alignItems: 'start' }}>
            <div>
              <WorldMap height={window.innerWidth < 700 ? 260 : 440} points={d.points.map((p: any) => ({ ...p, onClick: () => nav(`/incidents/${p.id}`) }))} />
              <div className="row wrap" style={{ gap: 12, fontSize: 12, marginTop: 6 }}>
                {(['critical', 'high', 'medium', 'low'] as const).map(l => <span key={l} className="row" style={{ gap: 4 }}><Sev level={l} /><b>{d.severity?.[l] ?? 0}</b></span>)}
              </div>
            </div>
            <div className="stack" style={{ gap: 16 }}>
              <div><div className="muted" style={{ fontSize: 11.5, marginBottom: 6 }}>What happened · click to list</div>
                <MiniBars rows={C.where.kinds.map((k: any) => ({ label: k.kind, a: k.n, key: k.kind }))} onClick={i => nav(`/incidents?kind=${encodeURIComponent(C.where.kinds[i].kind)}`)} /></div>
              <div><div className="muted" style={{ fontSize: 11.5, marginBottom: 6 }}>Where · victim country</div>
                <MiniBars rows={C.where.countries.slice(0, 8).map((c: any) => ({ label: countryName(c.country), a: c.n, key: c.country }))} /></div>
            </div>
          </div>
        </Step>
        <Step n={2} id="s-who" q="Who is being impacted?" to="/orgs" toLabel="Organisations" wide
          a={<><b>{d.now.critical_orgs}</b> organisations at Critical and <b>{lc.high || 0}</b> at High now; <b>{C.how.reached}</b> reached by an incident in the window.</>}>
          <Watchlist grid={d.grid} onOpen={id => nav(`/orgs/${id}`)} />
        </Step>
        <Step n={3} id="s-how" q="How are they being impacted?" to="/incidents" toLabel="How incidents reach organisations" wide
          a={<>Through {C.how.by_link.slice(0, 3).map((l: any) => `${l.label} (${l.orgs})`).join(', ')} — and, across their own exposure, mostly in the domains below.</>}>
          <div className="grid g-main-side" style={{ gap: 16 }}>
            {d.domains.heat.length ? (
              <div style={{ height: Math.max(260, 60 + d.domains.heat.length * 26) }}>
                <ResponsiveHeatMap data={d.domains.heat} margin={{ top: 68, right: 8, bottom: 4, left: 170 }} axisTop={{ tickRotation: -30, tickSize: 0, tickPadding: 6 }}
                  axisLeft={{ tickSize: 0, tickPadding: 8 }} colors={((c: any) => (c.value == null ? EMPTY : ramp(c.value))) as any} emptyColor={EMPTY}
                  borderWidth={2} borderColor={SURFACE} enableLabels valueFormat={(v: any) => (v == null ? '' : `${v}%`)}
                  labelTextColor={((c: any) => (c.value == null ? 'transparent' : onFill(ramp(c.value)))) as any} theme={nivoTheme as any} hoverTarget="cell" animate
                  onClick={() => nav('/exposure')}
                  tooltip={({ cell }: any) => <div className="tip"><strong>{cell.data.n} of {cell.data.of}</strong> {cell.serieId} organisations<div>Medium or above in {cell.data.x}</div></div>} />
              </div>) : <Empty>Awaiting surface scans.</Empty>}
            <div>
              <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>Organisations reached by an incident, by how it reaches them · last {range} days</div>
              <MiniBars rows={C.how.by_link.map((l: any) => ({ label: l.label, a: l.orgs, key: l.link }))} max={d.monitored} />
              <div className="muted" style={{ fontSize: 11.5, marginTop: 8 }}>Heatmap (now): share of each sector's organisations with a Medium-or-above finding in each risk domain.</div>
            </div>
          </div>
        </Step>
        <Step n={4} id="s-conc" q="Which shared providers concentrate the risk?" to="/incidents?view=providers" toLabel="Provider concentration"
          a={<>Unlike step 1 (where incidents land), this is where exposure is shared before anything happens: <b>{C.concentration.top[0]?.vendor}</b> is in the public DNS of{' '}
            <b>{C.concentration.top[0]?.orgs}</b> of {C.concentration.scanned} scanned organisations. <b>{C.concentration.active_n}</b> providers have an issue now.</>}>
          <MiniBars rows={C.concentration.top.map((p: any) => ({ label: p.vendor, a: p.orgs, key: p.vendor, title: `${p.category} · ${p.orgs} monitored organisations`,
            extra: p.worst ? <span style={{ marginLeft: 6 }}><Sev level={p.worst} compact /></span> : undefined }))} max={C.concentration.scanned}
            onClick={i => nav(`/orgs?provider=${encodeURIComponent(C.concentration.top[i].vendor)}`)} />
          {!!C.concentration.with_issue.length && (
            <div style={{ marginTop: 10 }}><div className="muted" style={{ fontSize: 11.5, marginBottom: 4 }}>Shared providers with an issue now</div>
              {C.concentration.with_issue.map((p: any) => (
                <a key={p.vendor} className="clickable" onClick={() => nav(`/incidents/${p.id}`)} style={{ display: 'block', fontSize: 12.5, color: 'var(--ink)' }}>
                  {p.worst && <Sev level={p.worst} compact />} <b>{p.vendor}</b> <span className="muted">· {p.orgs} organisations · {p.title}</span></a>))}
            </div>)}
        </Step>
        <Step n={5} id="s-fast" q="How fast are the issues moving?" to="/speed" toLabel="Speed & spread"
          a={<>A median <b>{P.exploit.median ?? '—'} days</b> from disclosure to exploitation ({P.exploit.share_7d != null ? `${Math.round(P.exploit.share_7d * 100)}%` : '—'} within a week); <b>{P.spread.spreading}</b> incidents spreading across publishers.</>}>
          <div className="stack" style={{ gap: 14 }}>
            <div><div className="muted" style={{ fontSize: 11.5, marginBottom: 6 }}>Disclosure → confirmed exploitation · {P.exploit.kev_window} CVEs newly exploited · (n) = running at monitored organisations</div>
              <BandRibbon bands={P.exploit.bins} unit="CVEs" extra={(b: any) => (b.at_orgs ? <span className="muted" style={{ fontSize: 11 }}>({b.at_orgs})</span> : null)} /></div>
            <div><div className="muted" style={{ fontSize: 11.5, marginBottom: 6 }}>First report → 3 independent publishers · incidents picked up by 2+ publishers</div>
              <BandRibbon bands={P.spread.bands} unit="incidents" /></div>
          </div>
        </Step>
        <Step n={6} id="s-next" q="Who is potentially next?" to="/speed#path" toLabel="Who is in the path"
          a={<><b>{C.next.total}</b> organisations are exposed to what is happening now without being named victims — each for an explainable reason, not a forecast.</>}>
          {!C.next.orgs.length ? <Empty>None in this window.</Empty> : (
            <div className="stack" style={{ gap: 7 }}>
              {C.next.orgs.slice(0, 7).map((o: any) => (
                <a key={o.id} className="clickable" onClick={() => nav(`/orgs/${o.id}`)} style={{ color: 'var(--ink)', fontSize: 12.5 }}>
                  <span className="row wrap" style={{ gap: 6 }}>{o.level && <Sev level={o.level} compact />}<b>{o.name}</b>
                    {o.kinds.map((k: string) => <span key={k} className="pill" style={{ fontSize: 10.5 }}>{k === 'path' ? 'in the path' : k === 'sector' ? 'sector under extortion' : 'provider incident'}</span>)}</span>
                  <span className="muted clamp2" style={{ marginLeft: 22 }}>{o.reasons[0]?.text}</span>
                </a>))}
              {!!C.next.sectors_under_extortion.length && <div className="muted" style={{ fontSize: 11.5 }}>Sectors under active extortion: {C.next.sectors_under_extortion.slice(0, 4).map((s: any) => `${s.sector} (${s.victims})`).join(' · ')}</div>}
            </div>)}
        </Step>
        <Step n={7} id="s-dep" q="What do those providers depend on?" to={fourth.length ? '/suppliers' : '/incidents?view=providers'} toLabel="Supply chain"
          a={f0 ? <><b>{f0.name}</b> hosts the DNS or mail of providers used by <b>{f0.indirect}</b> organisations that don't use it directly; <b>{P.supply.provider_incidents}</b> provider incidents reach {P.supply.provider_reach} organisations.</>
            : <><b>{P.supply.provider_incidents}</b> provider incidents reach {P.supply.provider_reach} organisations.</>}>
          <MiniBars rows={(fourth.length ? fourth.slice(0, 5).map((f: any) => ({ label: f.name, a: f.direct || 0, b: f.indirect || 0, key: f.name }))
            : P.supply.direct.slice(0, 5).map((p: any) => ({ label: p.name, a: p.direct, key: p.name })))} />
          {fourth.length > 0 && <div className="row wrap" style={{ gap: 10, fontSize: 11.5, marginTop: 6 }}><Swatch c={SERIES[0]} l="direct" /><Swatch c={INDIRECT()} l="via a provider's DNS or mail" /></div>}
        </Step>
        <Step n={8} id="s-actors" q="Who is behind it?" to="/adversaries" toLabel="Adversaries"
          a={<><b>{C.actors.active}</b> actors active in the window{C.actors.top[0] ? <>; most active: <b>{C.actors.top[0].name}</b></> : ''}.</>}>
          {C.actors.top.length ? <MiniBars rows={C.actors.top.map((a: any) => ({ label: a.name, a: a.victims_30d, b: a.mentions_30d, key: a.id }))} onClick={i => nav(`/adversaries/${C.actors.top[i].id}`)} />
            : <Empty>No actor activity in this window.</Empty>}
          <div className="row wrap" style={{ gap: 10, fontSize: 11.5, marginTop: 6 }}><Swatch c={SERIES[0]} l="leak-site victims" /><Swatch c={INDIRECT()} l="reporting mentions" /></div>
        </Step>
        <Step n={9} id="s-talk" q="What is being discussed on the dark web and forums?" to="/darkweb" toLabel="Dark web & chatter"
          a={<><b>{C.discussion.leak_listings}</b> leak-site listings and <b>{C.discussion.forum_claims}</b> forum or market claims; <b>{C.discussion.monitored_listed}</b> monitored organisations listed.</>}>
          <div className="row wrap" style={{ gap: 6, marginBottom: 8 }}>
            {Object.entries(C.discussion.claims).map(([k, n]: any) => <span key={k} className="pill">{k}: {n}</span>)}
          </div>
          <div className="muted" style={{ fontSize: 11.5, marginBottom: 4 }}>Community chatter themes · last {Math.min(Number(range), 14)} days</div>
          {C.discussion.chatter_themes.length ? <MiniBars rows={C.discussion.chatter_themes.map((t: any) => ({ label: t.theme, a: t.n, key: t.theme }))} /> : <span className="muted" style={{ fontSize: 12 }}>No chatter collected in the window.</span>}
        </Step>
        <Step n={10} id="s-analysts" q="What are analysts saying?" to="/analyst" toLabel="Analyst view" wide
          a={<><b>{C.analysts.items}</b> news, research and advisory items in the window{C.analysts.themes[0] ? <>; the leading theme is <b>{C.analysts.themes[0].theme}</b></> : ''}.</>}>
          <MiniBars rows={C.analysts.themes.map((t: any) => ({ label: t.theme, a: t.n, key: t.theme, extra: t.rising ? <span className="pill" style={{ marginLeft: 6, fontSize: 10.5 }}>rising</span> : undefined }))}
            onClick={i => nav(`/analyst?topic=${encodeURIComponent(C.analysts.themes[i].theme)}`)} />
        </Step>
      </div>

      <SectionLabel>The response — what it means for one organisation, and for the watchlist</SectionLabel>
      <div className="chain-grid">
        <Step n={11} id="s-org" q="So what — the risk for one organisation, and what it must do" to="/prevent" toLabel="Every organisation's actions" wide
          a={<><b>{d.now.act_72h}</b> organisations must act within 72 hours, <b>{d.now.overdue}</b> actions are overdue and <b>{d.now.verified_closed_30d}</b> fixes were verified in 30 days. Pick one — the most urgent is shown first.</>}>
          <OrgPicker d={d} />
          <div className="grid g2" style={{ marginTop: 14 }}>
            <Card title="Deadlines ahead" sub="now · actions due per day, by level" right={<a className="srclink" onClick={() => nav('/speed#due')}>Speed & spread <ArrowRight size={11} /></a>}>
              <StackedBars data={dueDays(d.act.calendar)} x="label" keys={['critical', 'high', 'medium']} names={['Critical', 'High', 'Medium']}
                colors={[SEV_COLOR.critical, SEV_COLOR.high, SEV_COLOR.medium]} height={180} onClick={() => nav('/speed#due')} />
            </Card>
            <Card title="Are vendor fixes being applied?" sub="exploited CVEs on monitored organisations' own hosts: fix published by the vendor → fix observed on a later scan"
              right={<a className="srclink" onClick={() => nav('/prevent#fixes')}>Vendor fixes <ArrowRight size={11} /></a>}>
              <FixPipeline f={d.fixes} top={4} />
            </Card>
          </div>
        </Step>
      </div>

      <SectionLabel>What changed in the last 24 hours</SectionLabel>
      <div className="grid g2">
        <Card title="New Critical / High findings" sub="first seen in the last 24 hours" right={<a className="srclink" onClick={() => nav('/orgs')}>All <ArrowRight size={11} /></a>}>
          {!d.changes.findings.length ? <Empty>None in the last 24 hours.</Empty> : (
            <div className="feed">{d.changes.findings.map((f: any) => (
              <div key={f.id} className="feed-item clickable" style={{ gridTemplateColumns: 'auto 1fr' }} onClick={() => nav(`/orgs/${f.org_id}`)}>
                <Sev level={f.severity} rule={f.rule_id} compact />
                <div><div className="t clamp2"><b>{f.org}</b> — {f.title}</div><div className="m"><span className="mono">{f.rule_id}</span><When ts={f.first_seen} /></div></div>
              </div>))}</div>)}
        </Card>
        <Card title="New incidents" sub="first seen in the last 24 hours" right={<a className="srclink" onClick={() => nav('/incidents')}>All <ArrowRight size={11} /></a>}>
          {!d.changes.incidents.length ? <Empty>None in the last 24 hours.</Empty> : (
            <div className="feed">{d.changes.incidents.map((i: any) => (
              <div key={i.id} className="feed-item clickable" style={{ gridTemplateColumns: 'auto 1fr' }} onClick={() => nav(`/incidents/${i.id}`)}>
                <Sev level={i.severity} compact />
                <div><div className="t clamp2">{i.title}</div><div className="m"><span>{i.kind}</span><When ts={i.first_seen} /></div></div>
              </div>))}</div>)}
        </Card>
      </div>

      <PageSources note="The Situation draws on every source; each page lists the ones it uses." />
    </div>
  )
}
