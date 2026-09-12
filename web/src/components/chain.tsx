import { useLocation, useNavigate } from 'react-router-dom'

/** The risk chain that orders the console: the threat → the exposure → the response. The landing page answers every step in brief;
 *  each page is one step, with a breadcrumb on top and "previous / next step" at the bottom so the data reads as one flow. */
export const CHAIN = [
  { to: '/incidents', label: 'Incidents & impact', q: 'Where are the issues, who is hit and how?', grp: 'The threat' },
  { to: '/speed', label: 'Speed & spread', q: 'How fast is it moving — and who is next?', grp: 'The threat' },
  { to: '/adversaries', label: 'Adversaries', q: 'Who is behind it?', grp: 'The threat' },
  { to: '/darkweb', label: 'Dark web & chatter', q: 'What is being discussed on the dark web and forums?', grp: 'The threat' },
  { to: '/analyst', label: 'Analyst view', q: 'What are analysts saying?', grp: 'The threat' },
  { to: '/exposure', label: 'Exposure & vulns', q: 'Where can it hit — exposed and exploited software?', grp: 'The exposure' },
  { to: '/impersonation', label: 'Impersonation & IOCs', q: 'Who is impersonating them?', grp: 'The exposure' },
  { to: '/suppliers', label: 'Supply chain', q: 'Where is the dependence?', grp: 'The exposure' },
  { to: '/ai', label: 'AI risk', q: 'What about the AI stack?', grp: 'The exposure' },
  { to: '/orgs', label: 'Organisations', q: 'What is the risk for each organisation?', grp: 'The response' },
  { to: '/prevent', label: 'Prevent & actions', q: 'What must they do, by when — and was it fixed?', grp: 'The response' },
]

export function ChainNav({ where }: { where: 'top' | 'bottom' }) {
  const loc = useLocation()
  const nav = useNavigate()
  const i = CHAIN.findIndex(c => loc.pathname === c.to || loc.pathname.startsWith(`${c.to}/`))
  if (i < 0) return null
  const c = CHAIN[i], prev = CHAIN[i - 1], next = CHAIN[i + 1]
  if (where === 'top') {
    return (
      <div className="chain-top">
        <a onClick={() => nav('/')}>Situation</a><span className="muted">›</span><span className="muted">{c.grp}</span><span className="muted">›</span>
        <span className="step-n sm">{i + 1}</span><b>{c.q}</b><span className="muted">· step {i + 1} of {CHAIN.length}</span>
      </div>
    )
  }
  return (
    <div className="chain-bottom">
      <a className="card clickable" onClick={() => nav(prev ? prev.to : '/')}>
        <div className="muted" style={{ fontSize: 11.5 }}>← {prev ? `Step ${i}` : 'Back to'}</div>
        <b>{prev ? prev.q : 'The situation'}</b><div className="muted" style={{ fontSize: 12 }}>{prev ? prev.label : 'All eleven questions in brief'}</div>
      </a>
      <a className="card clickable next" onClick={() => nav(next ? next.to : '/')}>
        <div className="muted" style={{ fontSize: 11.5 }}>{next ? `Step ${i + 2}` : 'Back to'} →</div>
        <b>{next ? next.q : 'The situation'}</b><div className="muted" style={{ fontSize: 12 }}>{next ? next.label : 'All eleven questions in brief'}</div>
      </a>
    </div>
  )
}
