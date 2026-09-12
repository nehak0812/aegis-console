import { useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { ResponsiveHeatMap } from '@nivo/heatmap'
import { ResponsiveBump } from '@nivo/bump'
import { TrendingUp, Repeat, Sparkles } from 'lucide-react'
import { useApi, qs } from '../lib/api'
import { useRange } from '../App'
import { PageSources } from '../components/ui'
import { Card, Stat, Empty, SourceLink, When, Table, Tabs } from '../components/ui'
import { HBar } from '../components/charts'
import { nivoTheme, SERIES, BLUE_RAMP, EMPTY, SURFACE, onFill } from '../lib/chartTheme'

export default function Analyst() {
  const { range } = useRange()
  const nav = useNavigate()
  const [sp, setSp] = useSearchParams()
  const theme = sp.get('topic') || ''  // not "theme": ?theme= is the colour theme (dark / dim / light)
  const [ent, setEnt] = useState<'actors' | 'vendors' | 'cves'>('actors')
  const [cell, setCell] = useState<{ publisher: string; theme: string } | null>(null)
  const [family, setFamily] = useState('')
  const { data } = useApi<any>(`/analyst${qs({ days: range, family })}`, 300)
  const { data: items } = useApi<any[]>(theme || cell ? `/items${qs({ theme: cell?.theme || theme, publisher: cell?.publisher, days: range, limit: 60 })}` : null, 300)
  const stats = useMemo(() => {
    const t = data?.themes || []
    return { rising: t.filter((x: any) => x.rising), recurring: t.filter((x: any) => x.recurring), pubs: data?.who?.length || 0 }
  }, [data])
  if (!data) return <div className="muted">Reading the reporting…</div>
  const hmax = Math.max(1, ...data.matrix.flatMap((r: any) => r.data.map((c: any) => c.y)))
  // sequential single-hue ramp on the dark surface: 0 recedes into the surface, more = brighter blue
  const heatColor = (v: number) => (v ? BLUE_RAMP[Math.min(BLUE_RAMP.length - 1, Math.round((Math.sqrt(v) / Math.sqrt(hmax)) * (BLUE_RAMP.length - 1)))] : EMPTY)
  const setTheme = (t: string) => { setCell(null); const n = new URLSearchParams(sp); t ? n.set('topic', t) : n.delete('topic'); setSp(n) }

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">Analyst view</div>
          <h2>Key themes, recurring aspects, and who is publishing what</h2>
          <p>{data.window_items.toLocaleString()} items from vendor research (CrowdStrike, Mandiant, Microsoft, Unit 42, Talos…), government CERTs, security news, dark-web reporting and community channels, tagged by transparent keyword rules. Momentum compares this week with the prior four-week average.</p>
        </div>
      </div>
      <div className="grid g4" style={{ marginBottom: 14 }}>
        <Stat label="Items analysed" value={data.window_items.toLocaleString()} hint={`last ${range} days`} />
        <Stat label="Rising themes" value={data.mature ? stats.rising.length : '—'}
          hint={data.mature ? (stats.rising.slice(0, 2).map((t: any) => t.theme).join(' · ') || '—') : `baseline maturing: ${data.history_days} of 28 days collected`} />
        <Stat label="Recurring themes" value={stats.recurring.length} hint="present in 6+ of the last 8 weeks" />
        <Stat label="Active publishers" value={stats.pubs} hint="in the publisher matrix" />
      </div>

      <div className="grid" style={{ marginBottom: 14 }}>
        <Card title="Theme board" sub="click a theme to read the underlying reporting">
          <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 8 }}>
            {data.themes.slice(0, 24).map((t: any) => (
              <div key={t.theme} className={`cat-tile ${theme === t.theme ? 'on' : ''}`} onClick={() => setTheme(theme === t.theme ? '' : t.theme)}>
                <span className="muted" style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: '.08em' }}>{t.family}</span>
                <span style={{ fontWeight: 600 }}>{t.theme}</span>
                <span className="row" style={{ gap: 8, fontSize: 12 }}>
                  <b>{t.n}</b><span className="muted">items</span>
                  <span className="muted" title="this week vs prior 4-week average">{t.this_week} this wk</span>
                  {t.rising && <span className="pill" title="momentum ≥ 1.8×"><TrendingUp size={11} />rising</span>}
                  {t.recurring && <span className="pill" title="present in 6+ of 8 weeks"><Repeat size={11} />recurring</span>}
                </span>
              </div>))}
          </div>
        </Card>
        <Card title="Rank of the top themes, week by week" sub="recurring aspects hold their line; new ones climb · click a line to read it">
          <div style={{ height: 330 }}>
            <ResponsiveBump data={data.bump} margin={{ top: 12, right: 220, bottom: 30, left: 36 }} colors={SERIES} lineWidth={2} activeLineWidth={4} inactiveLineWidth={2}
              inactiveOpacity={0.2} pointSize={8} activePointSize={12} pointBorderWidth={2} pointBorderColor={SURFACE} theme={nivoTheme as any}
              axisTop={null} axisBottom={{ tickSize: 0, tickPadding: 8 }} axisLeft={{ tickSize: 0, tickPadding: 6 }} endLabelPadding={8}
              onClick={(s: any) => setTheme(s.id)} animate motionConfig="gentle" />
          </div>
        </Card>
      </div>

      <Card title="Who is publishing what" sub={family ? `publisher × every ${family} theme · click a cell to read them` : 'publisher × theme — top 10 themes plus the leading theme of every family · click a cell to read them'}
        right={<select className="txt" aria-label="Theme family" value={family} onChange={e => setFamily(e.target.value)}>
          <option value="">All families</option>{(data.families || []).map((f: string) => <option key={f} value={f}>{f}</option>)}</select>}>
        <div style={{ height: Math.max(360, data.matrix.length * 24 + 130) }}>
          <ResponsiveHeatMap data={data.matrix} margin={{ top: 120, right: 20, bottom: 10, left: 220 }}
            axisTop={{ tickRotation: -40, tickSize: 0, tickPadding: 6 }} axisLeft={{ tickSize: 0, tickPadding: 8 }}
            colors={((cell: any) => heatColor(cell.value || 0)) as any} emptyColor={EMPTY} borderWidth={2} borderColor={SURFACE}
            labelTextColor={((cell: any) => (cell.value ? onFill(heatColor(cell.value)) : 'transparent')) as any} enableLabels theme={nivoTheme as any} hoverTarget="cell" animate
            onClick={(c: any) => setCell({ publisher: c.serieId, theme: c.data.x })}
            tooltip={({ cell }: any) => <div className="tip"><strong>{cell.value}</strong> items · {cell.serieId}<div>{cell.data.x}</div></div>} />
        </div>
      </Card>

      <div className="grid g-main-side" style={{ marginTop: 14 }}>
        <Card title={cell ? `${cell.publisher} on ${cell.theme}` : theme ? `Reporting on: ${theme}` : 'Read the reporting'} sub={cell || theme ? 'newest first · open the original' : 'select a theme or a matrix cell'}
          right={(cell || theme) && <a className="srclink" onClick={() => { setCell(null); setTheme('') }}>clear</a>}>
          {!(cell || theme) ? <Empty>Select a theme tile, a line in the rank chart, or a cell in the publisher matrix.</Empty> : (
            <div className="feed">{(items || []).map((i: any) => (
              <div key={i.id} className="feed-item"><span className="pill">{i.pub_type}</span>
                <div><div className="t">{i.title}</div><div className="m"><span>{i.publisher}</span><When ts={i.published} /></div>{i.summary && <div className="m clamp2">{i.summary}</div>}</div>
                <SourceLink url={i.url} /></div>))}</div>)}
        </Card>
        <div className="stack" style={{ gap: 14 }}>
          <Card title="Consensus" sub="named by the most distinct publishers">
            <Tabs value={ent} onChange={setEnt} tabs={[{ id: 'actors', label: 'Actors' }, { id: 'vendors', label: 'Vendors' }, { id: 'cves', label: 'CVEs' }]} />
            <HBar data={(data.entities[ent] || []).slice(0, 12)} label="label" value="publishers"
              onClick={d => ent === 'actors' ? nav(`/adversaries/${d.key}`) : ent === 'cves' ? nav(`/exposure?cve=${d.key}`) : nav(`/incidents?provider=${encodeURIComponent(d.key)}`)} />
          </Card>
          <Card title="Themes that travel together" sub="co-occurrence ranked by lift"><Sparkles size={0} />
            <div className="feed">{data.cooccurrence.slice(0, 10).map((c: any, i: number) => (
              <div key={i} className="feed-item" style={{ gridTemplateColumns: '1fr auto' }}>
                <div className="t" style={{ fontWeight: 400 }}><a className="clickable" onClick={() => setTheme(c.a)}>{c.a}</a> <span className="muted">+</span> <a className="clickable" onClick={() => setTheme(c.b)}>{c.b}</a></div>
                <span className="muted" style={{ fontSize: 12 }}>{c.n} items · ×{c.lift}</span></div>))}</div>
          </Card>
        </div>
      </div>

      <Card title="Publisher focus" sub="each publisher's three most frequent themes in the window" className="" >
        <Table rows={data.who} cols={[
          { key: 'publisher', label: 'Publisher' }, { key: 'type', label: 'Type', render: (w: any) => <span className="pill">{w.type}</span> },
          { key: 'items', label: 'Items', num: true }, { key: 'focus', label: 'Focus', render: (w: any) => <span className="row wrap" style={{ gap: 4 }}>{w.focus.map((f: string) => <span key={f} className="pill btn" onClick={e => { e.stopPropagation(); setTheme(f) }}>{f}</span>)}</span> }]} />
      </Card>
      <PageSources cats={['News', 'Research', 'Government', 'Chatter']} />
    </div>
  )
}
