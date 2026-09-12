import type { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowRight, Zap } from 'lucide-react'
import { useApi } from '../lib/api'
import { useRange } from '../App'
import { Sev, ActBy, Confidence } from './ui'
import { day } from '../lib/format'

const KIND_LABEL: Record<string, string> = { path: 'in the path of a fast-moving incident', sector: 'sector under active extortion + exploitable exposure', provider: 'a provider it uses has an incident' }

function Part({ title, to, toLabel, children }: { title: string; to?: string; toLabel?: string; children: ReactNode }) {
  const nav = useNavigate()
  return (
    <div style={{ minWidth: 0 }}>
      <div className="row" style={{ justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
        <div className="muted" style={{ fontSize: 11.5, textTransform: 'uppercase', letterSpacing: '.06em' }}>{title}</div>
        {to && <a className="srclink" style={{ fontSize: 12 }} onClick={() => nav(to)}>{toLabel || 'Open'} <ArrowRight size={11} /></a>}
      </div>
      {children}
    </div>
  )
}

/** One organisation's risk and what it must do — the whole chain boiled down, each part linking to its evidence. */
export function OrgBrief({ id, showOpen = true }: { id: string; showOpen?: boolean }) {
  const nav = useNavigate()
  const { range } = useRange()
  const { data: b } = useApi<any>(`/orgs/${id}/brief?days=${range}`, 120)
  if (!b) return <div className="muted">Reading the organisation's risk…</div>
  const none = (t: string) => <div className="muted" style={{ fontSize: 12.5 }}>{t}</div>
  return (
    <div className="card" style={{ borderLeft: `4px solid var(--${b.level === 'critical' ? 'critical' : b.level === 'high' ? 'high' : b.level === 'medium' ? 'medium' : 'hair-2'})` }}>
      <div className="row wrap" style={{ gap: 10, alignItems: 'center', marginBottom: 6 }}>
        <h3 style={{ margin: 0, fontSize: 16 }}>{b.name}</h3>{b.level && <Sev level={b.level} rule={b.why?.rule_id} />}
        <span className="muted" style={{ fontSize: 12 }}>{b.sector} · risk brief · last {b.window} days</span>
        {showOpen && <a className="srclink" style={{ marginLeft: 'auto' }} onClick={() => nav(`/orgs/${b.id}`)}>Open the organisation <ArrowRight size={11} /></a>}
      </div>
      <div style={{ fontSize: 14, lineHeight: 1.5, marginBottom: 14 }}>{b.sentence}</div>
      <div className="grid g3" style={{ gap: 18 }}>
        <Part title={`What it must do · ${b.open} open`} to={`/orgs/${b.id}?tab=prevent`} toLabel="Actions">
          {!b.must_do.length ? none('No Critical, High or Medium finding — nothing to action.') : (
            <div className="stack" style={{ gap: 8 }}>{b.must_do.map((a: any) => (
              <div key={a.id} style={{ fontSize: 12.5 }}>
                <div className="row wrap" style={{ gap: 6 }}><ActBy ts={a.due} /><Sev level={a.level} rule={a.rule_id} compact /><Confidence c={a.confidence} /></div>
                <div style={{ marginTop: 3 }}><b>{a.title}</b></div>
                {a.first_step && <div className="muted">{a.owner_role}: {a.first_step}</div>}
              </div>))}</div>)}
        </Part>
        <Part title={`What reaches it · ${b.reached_n}`} to={`/orgs/${b.id}`} toLabel="Incidents">
          {!b.reached_by.length ? none(`No incident reaches it in the last ${b.window} days.`) : (
            <div className="stack" style={{ gap: 7 }}>{b.reached_by.map((r: any) => (
              <a key={r.id + r.link_type} className="clickable" style={{ fontSize: 12.5, color: 'var(--ink)' }} onClick={() => nav(`/incidents/${r.id}`)}>
                <span className="row" style={{ gap: 6 }}><Sev level={r.severity} compact /><span className="clamp2">{r.title}</span></span>
                <span className="muted" style={{ marginLeft: 22 }}>{r.how}{r.fast && <> · <Zap size={11} style={{ color: 'var(--accent)' }} /> fast-moving</>}</span>
              </a>))}</div>)}
          {!!b.exposures.length && (
            <div style={{ marginTop: 10 }}><div className="muted" style={{ fontSize: 11.5 }}>Own exposures (Critical / High)</div>
              {b.exposures.slice(0, 3).map((f: any, i: number) => <div key={i} style={{ fontSize: 12.5 }}><Sev level={f.severity} rule={f.rule_id} compact /> {f.title}</div>)}</div>)}
        </Part>
        <Part title="Dependence, actors and chatter" to="/suppliers" toLabel="Supply chain">
          <div className="stack" style={{ gap: 7, fontSize: 12.5 }}>
            <div><b>{b.dependence.providers}</b> providers in its DNS{b.dependence.issues.length ? <>; <b>{b.dependence.issues.length}</b> with an incident now</> : ''}.
              {!!b.dependence.fourth.length && <span className="muted"> Their DNS and mail run on {b.dependence.fourth.slice(0, 3).map((f: any) => f.name).join(', ')}.</span>}</div>
            {b.actors.listed.length ? <div><b>Listed on a leak site</b> by {b.actors.listed[0].actor} ({day(b.actors.listed[0].published)}).</div>
              : b.actors.sector_groups.length ? <div>Most active against {b.sector}: {b.actors.sector_groups.map((g: any) => `${g.group} (${g.victims})`).join(', ')}.</div>
              : <div className="muted">No extortion group listed a {b.sector} organisation in the window.</div>}
            <div>{b.discussion.mentions ? <>Named in <b>{b.discussion.mentions}</b> reports and posts{b.discussion.forum_or_chatter ? ` (${b.discussion.forum_or_chatter} forum or chatter)` : ''}.</> : <span className="muted">Not named in collected reporting or chatter.</span>}</div>
            {!!b.line_of_fire.length && (
              <div style={{ marginTop: 2 }}><div className="muted" style={{ fontSize: 11.5 }}>Exposed to what is happening now because</div>
                {b.line_of_fire.slice(0, 3).map((r: any, i: number) => <a key={i} className="clickable" style={{ display: 'block', color: 'var(--ink-2)' }} onClick={() => nav(r.to)}>· {KIND_LABEL[r.kind] || r.kind}: {r.text}</a>)}</div>)}
          </div>
        </Part>
      </div>
    </div>
  )
}
