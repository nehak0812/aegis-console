import { useNavigate } from 'react-router-dom'
import { Empty, SourceLink, Table, Sev } from './ui'
import { SERIES } from '../lib/chartTheme'
import { day } from '../lib/format'

export const FIX_SHORT: Record<string, string> = { patch: 'vendor patch', advisory: 'vendor advisory', none: 'no vendor fix found', unchecked: 'not yet checked' }
const STILL = () => SERIES[4] || SERIES[1]
const Swatch = ({ c, l }: { c: string; l: string }) => <span className="row" style={{ gap: 4 }}><span style={{ width: 9, height: 9, borderRadius: 2, background: c }} />{l}</span>

/** Exploited CVE → vendor fix published → organisations exposed → fix observed (no longer on a later scan) vs still exposed. */
export function FixPipeline({ f, top = 5 }: { f: any; top?: number }) {
  const nav = useNavigate()
  if (!f?.summary?.cves) return <Empty>No exploited CVE is reported on a monitored organisation's own hosts yet.</Empty>
  const s = f.summary
  const stages = [
    { k: s.cves, l: 'exploited CVEs reported on monitored organisations\' own hosts', base: s.cves, c: SERIES[0] },
    { k: s.with_fix, l: `with a vendor patch or advisory published${s.unchecked ? ` · ${s.unchecked} not yet checked` : ''}`, base: s.cves, c: SERIES[0] },
    { k: s.exposures, l: 'organisation × CVE exposures tracked', base: s.exposures, c: SERIES[0] },
    { k: s.fixed, l: 'fix observed — no longer reported on a later scan (patched or host removed)', base: s.exposures, c: SERIES[0] },
    { k: s.still, l: `still exposed${s.median_days_exposed != null ? ` · median ${s.median_days_exposed} day${s.median_days_exposed === 1 ? '' : 's'} observed exposed` : ''}${s.cisa_overdue ? ` · ${s.cisa_overdue} past CISA's due date` : ''}`, base: s.exposures, c: STILL() },
  ]
  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className="stack" style={{ gap: 7 }}>
        {stages.map((st, i) => (
          <div key={i} style={{ display: 'grid', gridTemplateColumns: '46px minmax(0,1fr)', gap: 8, alignItems: 'center', fontSize: 12.5 }}>
            <b style={{ textAlign: 'right', fontSize: 15 }}>{st.k}</b>
            <div>
              <div style={{ height: 8, background: 'var(--hair)', borderRadius: 4 }}><div style={{ width: `${st.base ? (st.k / st.base) * 100 : 0}%`, height: '100%', background: st.c, borderRadius: 4 }} /></div>
              <div className="muted" style={{ fontSize: 11.5, marginTop: 2 }}>{st.l}</div>
            </div>
          </div>))}
      </div>
      {top > 0 && (
        <>
          <div className="muted" style={{ fontSize: 11.5 }}>CVEs with the most organisations still exposed</div>
          {f.cves.slice(0, top).map((c: any) => (
            <div key={c.cve} className="clickable" onClick={() => nav(`/exposure?cve=${c.cve}`)} title={`${c.fix.label || FIX_SHORT[c.fix.state]} · ${c.fixed} fixed · ${c.exposed_now} still exposed`}
              style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1.4fr) minmax(0,1fr) auto', gap: 8, alignItems: 'center', fontSize: 12.5 }}>
              <span className="trunc"><span className="mono">{c.cve}</span> <span className="muted">{c.vendor} {c.product}</span></span>
              <div style={{ display: 'flex', height: 8, background: 'var(--hair)', borderRadius: 4, overflow: 'hidden', gap: c.fixed && c.exposed_now ? 2 : 0 }}>
                <div style={{ flex: c.fixed, background: SERIES[0] }} /><div style={{ flex: c.exposed_now, background: STILL() }} />
              </div>
              <span className="pill" style={{ fontSize: 10.5 }}>{FIX_SHORT[c.fix.state]}</span>
            </div>))}
        </>)}
      <div className="row wrap" style={{ gap: 10, fontSize: 11.5 }}>
        <Swatch c={SERIES[0]} l="fix observed" /><Swatch c={STILL()} l="still exposed" />
        {s.tracking_since && <span className="muted">exposure history since {day(s.tracking_since)} — fixes appear as organisations are re-scanned</span>}
      </div>
    </div>
  )
}

/** Every exploited CVE on a monitored organisation's own hosts: the vendor's fix, who still exposes it, who no longer does. */
export function FixTable({ rows }: { rows: any[] }) {
  const nav = useNavigate()
  return (
    <Table rows={rows} max={200} empty="No exploited CVE is reported on a monitored organisation's own hosts." cols={[
      { key: 'cve', label: 'CVE', render: (c: any) => <><a className="clickable mono" onClick={() => nav(`/exposure?cve=${c.cve}`)}>{c.cve}</a><div className="muted" style={{ fontSize: 11.5 }}>{c.vendor} {c.product}</div></> },
      { key: 'severity', label: 'Level', render: (c: any) => (c.severity ? <Sev level={c.severity} /> : ''), sort: (c: any) => ['critical', 'high', 'medium', 'low'].indexOf(c.severity) },
      { key: 'fix', label: 'Vendor fix', render: (c: any) => (
        <div><span className="pill">{FIX_SHORT[c.fix.state]}</span>{c.fix.urls?.[0] && <div><SourceLink url={c.fix.urls[0].url} label={(c.fix.urls[0].tags || []).join(', ') || 'advisory'} /></div>}
          {!!c.fix.fixed_versions?.length && <div className="muted" style={{ fontSize: 11.5 }} title="affected ranges from the CVE record — the fix is at each upper bound">affected: {c.fix.fixed_versions.slice(0, 2).join('; ')}</div>}</div>), sort: (c: any) => c.fix.state },
      { key: 'kev_added', label: 'Exploited since', render: (c: any) => day(c.kev_added) },
      { key: 'exposed_now', label: 'Still exposed', render: (c: any) => (
        <div className="row wrap" style={{ gap: 4 }}>{c.still.slice(0, 4).map((o: any) => <span key={o.id} className="pill btn" onClick={e => { e.stopPropagation(); nav(`/orgs/${o.id}?tab=prevent`) }}>{o.name}</span>)}
          {c.exposed_now > 4 && <span className="muted" style={{ fontSize: 11.5 }}>+{c.exposed_now - 4}</span>}{!c.exposed_now && <span className="muted">none</span>}</div>), sort: (c: any) => c.exposed_now },
      { key: 'fixed', label: 'Fix observed', num: true, render: (c: any) => (c.fixed ? <span title={c.done.map((o: any) => `${o.name} (${day(o.fixed_at)})`).join(', ')}>{c.fixed}</span> : <span className="muted">0</span>) },
      { key: 'days_exposed', label: 'Days exposed', num: true, render: (c: any) => (c.days_exposed != null ? c.days_exposed : '—') },
      { key: 'cisa_overdue', label: 'CISA due', render: (c: any) => (c.cisa_overdue ? <span className="pill" style={{ borderColor: 'var(--critical)' }}>past {day(c.kev_due)}</span> : day(c.kev_due)), sort: (c: any) => (c.cisa_overdue ? 0 : 1) },
    ]} />
  )
}
