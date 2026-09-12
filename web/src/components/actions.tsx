import { Fragment, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { api } from '../lib/api'
import { Sev, ActBy, Confidence } from './ui'
import { day } from '../lib/format'

export const STATUSES = ['new', 'acknowledged', 'in_progress', 'resolved', 'accepted_risk', 'false_positive']
export const STATUS_LABEL: Record<string, string> = {
  new: 'New', acknowledged: 'Acknowledged', in_progress: 'In progress', resolved: 'Resolved', accepted_risk: 'Accepted risk', false_positive: 'False positive',
}

/** Change an action's status. There is no sign-in: the name typed once is kept in this browser and written to the action history. */
async function changeStatus(a: any, status: string, done: () => void, setMsg: (m: string) => void) {
  let by = ''
  try { by = localStorage.getItem('aegis_name') || '' } catch { /* storage blocked */ }
  if (!by) {
    by = (window.prompt('Your name, for the action history (there is no sign-in):') || '').trim()
    if (!by) return
    try { localStorage.setItem('aegis_name', by) } catch { /* storage blocked */ }
  }
  let reason: string | undefined, expires: string | undefined
  if (status === 'false_positive' || status === 'accepted_risk') {
    reason = (window.prompt(status === 'false_positive' ? 'Why is this a false positive?' : 'Why is the risk accepted (compensating control, vendor fix pending…)?') || '').trim()
    if (!reason) return
  }
  if (status === 'accepted_risk') {
    expires = (window.prompt('Accept the risk until (YYYY-MM-DD):', new Date(Date.now() + 90 * 864e5).toISOString().slice(0, 10)) || '').trim()
    if (!expires) return
  }
  try {
    await api(`/actions/${a.id}/status`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status, by, reason, expires }) })
    setMsg('')
  } catch (e: any) {
    setMsg(`${a.title}: ${String(e.message || e)}`)
  }
  done()
}

/** The action queue: due clock, level + confidence, owner, inline status; expand for the playbook and the history. */
export function ActionTable({ rows, onChanged, showOrg = true, max = 150 }: { rows: any[]; onChanged: () => void; showOrg?: boolean; max?: number }) {
  const nav = useNavigate()
  const [open, setOpen] = useState<string | null>(null)
  const [msg, setMsg] = useState('')
  const [n, setN] = useState(max)
  const cols = showOrg ? 7 : 6
  return (
    <>
      {msg && <div className="why" style={{ borderColor: 'var(--high)', marginBottom: 8 }}>{msg}</div>}
      <div className="tbl-wrap">
        <table className="tbl">
          <thead><tr><th style={{ width: 22 }} /><th>Due</th><th>Level</th>{showOrg && <th>Organisation</th>}<th>What to do</th><th>Owner</th><th>Status</th></tr></thead>
          <tbody>
            {rows.slice(0, n).map(a => (
              <Fragment key={a.id}>
                <tr className="click" onClick={() => setOpen(open === a.id ? null : a.id)}>
                  <td>{open === a.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</td>
                  <td>{a.status === 'resolved' && a.verified_closed_at ? <span className="pill">verified closed · {day(a.verified_closed_at)}</span>
                    : a.open ? <ActBy ts={a.due} /> : <span className="muted">—</span>}</td>
                  <td><div className="row" style={{ gap: 6 }}><Sev level={a.level} rule={a.rule_id} /><Confidence c={a.confidence} /></div></td>
                  {showOrg && <td><a className="clickable" onClick={e => { e.stopPropagation(); nav(`/orgs/${a.org_id}?tab=prevent`) }}><b>{a.org || a.org_id}</b></a></td>}
                  <td><span className="clamp2">{a.title}</span>
                    <div className="muted" style={{ fontSize: 11.5 }}><span className="mono">{a.rule_id}</span>{a.playbook?.effort_label ? ` · effort: ${a.playbook.effort_label}` : ''}{a.reopened ? ` · reopened ${a.reopened}×` : ''}</div></td>
                  <td className="ink2" style={{ fontSize: 12.5 }}>{a.owner_role || '—'}{a.owner && <div className="muted">{a.owner}</div>}</td>
                  <td onClick={e => e.stopPropagation()}>
                    <select className="txt" value={a.status} aria-label="Status" onChange={e => changeStatus(a, e.target.value, onChanged, setMsg)}>
                      {STATUSES.map(s => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
                    </select>
                  </td>
                </tr>
                {open === a.id && (
                  <tr><td /><td colSpan={cols - 1}>
                    <div className="grid g2" style={{ gap: 16, padding: '6px 0 12px' }}>
                      <div>
                        {a.playbook ? (
                          <>
                            <div className="muted" style={{ fontSize: 12 }}>What this prevents</div>
                            <div style={{ fontSize: 13, marginBottom: 8 }}>{a.playbook.prevents}</div>
                            <div className="muted" style={{ fontSize: 12 }}>Playbook · {a.playbook.owner} · effort {a.playbook.effort} ({a.playbook.effort_label})</div>
                            <ol style={{ margin: '4px 0 8px 18px', padding: 0, fontSize: 13 }}>{(a.playbook.steps || []).map((s: string, i: number) => <li key={i}>{s}</li>)}</ol>
                            {!!a.playbook.controls?.length && <div className="muted" style={{ fontSize: 11.5 }}>Indicative references: {a.playbook.controls.join(' · ')}</div>}
                          </>) : <div className="muted">No playbook for {a.rule_id}.</div>}
                      </div>
                      <div>
                        <div className="muted" style={{ fontSize: 12 }}>History</div>
                        <div className="stack" style={{ gap: 4, fontSize: 12.5 }}>{(a.history || []).slice().reverse().map((h: any, i: number) => (
                          <div key={i}><b>{STATUS_LABEL[h.status] || h.status}</b> · {h.by} · <span className="muted">{day(h.at)}</span>{h.note && <div className="muted">{h.note}</div>}</div>))}</div>
                        <div className="muted" style={{ fontSize: 11.5, marginTop: 8 }}>Closure is verified by AEGIS: when the finding is no longer observed on a later scan the action closes itself; if it returns, it reopens.</div>
                      </div>
                    </div>
                  </td></tr>)}
              </Fragment>))}
          </tbody>
        </table>
      </div>
      {rows.length > n && <button className="btn" style={{ marginTop: 8 }} onClick={() => setN(v => v + 150)}>Show more ({rows.length - n} left)</button>}
    </>
  )
}
