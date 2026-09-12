import { useState } from 'react'
import { ResponsiveHeatMap } from '@nivo/heatmap'
import { useApi, qs } from '../lib/api'
import { useRange } from '../App'
import { Card, Seg, Empty, StoryStrip, SectionLabel, PageSources, SevBar } from '../components/ui'
import { ActionTable, STATUS_LABEL } from '../components/actions'
import { FixPipeline, FixTable } from '../components/fixes'
import { SERIES, BLUE_RAMP, EMPTY, SURFACE, nivoTheme, onFill } from '../lib/chartTheme'

const SHORT: Record<string, string> = {
  dmarc_enforced: 'DMARC enforced', spf_strict: 'SPF -all', dkim: 'DKIM', mta_sts: 'MTA-STS', tls_rpt: 'TLS-RPT', dnssec: 'DNSSEC',
  caa: 'CAA', ns_redundant: 'Multi-provider DNS', domain_locked: 'Transfer lock',
}

export default function Prevent() {
  const [level, setLevel] = useState('')
  const [owner, setOwner] = useState('')
  const [status, setStatus] = useState('')
  const [overdue, setOverdue] = useState(false)
  const { range } = useRange()
  const { data: pv } = useApi<any>(`/prevent?days=${range}`, 300)
  const { data: q, refetch } = useApi<any>(`/actions${qs({ level, owner_role: owner, status, overdue, open_only: status ? false : true, limit: 1500 })}`, 120)
  const { data: fx } = useApi<any>(`/fixes?days=${range}`, 600)
  if (!pv) return <div className="muted">Measuring preventive controls…</div>
  const k = pv.kpi || {}
  const ctrl = [...pv.controls].filter((c: any) => c.pct != null).sort((a: any, b: any) => a.pct - b.pct)
  const weakest = ctrl[0], strongest = ctrl[ctrl.length - 1]
  const sectors = Array.from(new Set(pv.controls.flatMap((c: any) => Object.keys(c.by_sector || {})))).filter(s => s !== 'Unknown').sort() as string[]
  const heat = sectors.map(s => ({ id: s, data: pv.controls.map((c: any) => ({ x: SHORT[c.id] || c.label, y: c.by_sector?.[s]?.pct ?? null, n: c.by_sector?.[s]?.total })) }))
  const ramp = (p: number) => BLUE_RAMP[Math.min(BLUE_RAMP.length - 1, Math.floor((p / 100) * (BLUE_RAMP.length - 1)))]
  const maxOwner = Math.max(1, ...pv.by_owner.map((o: any) => o.critical + o.high + o.medium))

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">Prevent · now</div>
          <h2>What to fix, who owns it, by when — and proof that it was fixed</h2>
          <p>Every Critical, High and Medium finding becomes an action with an owner role, a playbook and a due date from its deadline rule. AEGIS closes an action
            itself when the finding is no longer observed on a later scan, and reopens it if it comes back. Preventive controls are measured passively from public
            DNS and RDAP and shown as adoption percentages — never as a score.</p>
        </div>
      </div>

      <StoryStrip items={[
        { label: 'Open actions', value: (k.open || 0).toLocaleString(), title: 'to work on now', sub: `${k.by_level?.critical || 0} Critical · ${k.by_level?.high || 0} High · ${k.by_level?.medium || 0} Medium`,
          onClick: () => { setStatus(''); setOverdue(false) } },
        { label: 'Overdue', value: k.overdue || 0, title: 'past their act-by date', sub: 'click to show only these', onClick: () => { setStatus(''); setOverdue(true) } },
        { label: `Verified closed · ${range}d`, value: k.verified_closed_30d || 0, title: 'fixes proven by a later scan',
          sub: `${k.raised_window ?? 0} raised in the same ${range} days${k.median_days_to_close != null ? ` · median ${k.median_days_to_close} days to a proven fix` : ''}`, onClick: () => setStatus('resolved') },
        { label: 'Weakest control', value: weakest ? `${weakest.pct}%` : '—', title: weakest?.label || '—',
          sub: strongest ? `strongest: ${strongest.label} ${strongest.pct}% · ${pv.scanned} organisations measured` : '' },
      ]} />

      <div className="grid g-main-side" style={{ marginBottom: 14 }}>
        <Card title="Preventive controls across the estate" sub={`share of the ${pv.scanned} organisations measured that have each control · weakest first · what each one prevents`}>
          <div className="stack" style={{ gap: 10 }}>
            {ctrl.map((c: any) => (
              <div key={c.id} style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.4fr) minmax(0, 2fr) 90px', gap: 12, alignItems: 'center' }}>
                <div><div style={{ fontSize: 13, fontWeight: 600 }}>{c.label}</div><div className="muted" style={{ fontSize: 11.5 }}>prevents: {c.prevents}</div></div>
                <div style={{ height: 12, background: 'var(--hair)', borderRadius: 6 }}><div style={{ width: `${c.pct}%`, height: '100%', background: SERIES[0], borderRadius: 6 }} /></div>
                <div style={{ textAlign: 'right' }}><b>{c.pct}%</b> <span className="muted" style={{ fontSize: 11.5 }}>{c.adopted}/{c.total}</span></div>
              </div>))}
            {pv.controls.some((c: any) => c.pct == null) && <div className="muted" style={{ fontSize: 12 }}>Not yet measured: {pv.controls.filter((c: any) => c.pct == null).map((c: any) => c.label).join(', ')} (collected by the daily hardening check).</div>}
          </div>
        </Card>
        <Card title="Where the work sits" sub="open findings by the role that owns the fix · stacked by level">
          <div className="stack" style={{ gap: 12 }}>
            {pv.by_owner.map((o: any) => (
              <div key={o.owner} className="clickable" onClick={() => setOwner(owner === o.owner ? '' : o.owner)} style={{ opacity: owner && owner !== o.owner ? 0.5 : 1 }}>
                <div className="row" style={{ justifyContent: 'space-between', fontSize: 12.5 }}><b>{o.owner}</b><span className="muted">{o.orgs} orgs</span></div>
                <div style={{ width: `${Math.max(4, ((o.critical + o.high + o.medium) / maxOwner) * 100)}%`, margin: '4px 0 3px' }}>
                  <SevBar counts={{ critical: o.critical, high: o.high, medium: o.medium }} height={10} />
                </div>
                <div className="muted" style={{ fontSize: 11.5 }}>{o.critical} Critical · {o.high} High · {o.medium} Medium · top: {o.top_rules.slice(0, 2).map((r: any) => r.rule_id).join(', ')}</div>
              </div>))}
          </div>
        </Card>
      </div>

      <Card title="Control adoption by sector" sub="% of measured organisations in each sector with the control · darker = more adopted · compare a sector with the estate">
        {heat.length ? (
          <div style={{ height: Math.max(260, 60 + heat.length * 30) }}>
            <ResponsiveHeatMap data={heat as any} margin={{ top: 70, right: 10, bottom: 6, left: 190 }} axisTop={{ tickRotation: -30, tickSize: 0, tickPadding: 6 }}
              axisLeft={{ tickSize: 0, tickPadding: 8 }} colors={((c: any) => (c.value == null ? EMPTY : ramp(c.value))) as any} emptyColor={EMPTY}
              borderWidth={2} borderColor={SURFACE} enableLabels valueFormat={(v: any) => (v == null ? '' : `${v}%`)}
              labelTextColor={((c: any) => (c.value == null ? 'transparent' : onFill(ramp(c.value)))) as any} theme={nivoTheme as any} hoverTarget="cell" animate
              tooltip={({ cell }: any) => <div className="tip"><strong>{cell.value}%</strong> · {cell.serieId}<div>{cell.data.x} · {cell.data.n} measured</div></div>} />
          </div>) : <Empty>Awaiting the first surface scans.</Empty>}
      </Card>

      <section id="fixes" style={{ scrollMarginTop: 80 }}>
        <SectionLabel>Vendor fixes · has the vendor released a fix, and have organisations applied it?</SectionLabel>
        <div className="grid g-main-side" style={{ marginBottom: 14 }}>
          <Card title="Are vendor fixes being applied?" sub="exploited CVEs (CISA KEV) reported on monitored organisations' own hosts">
            {fx ? <FixPipeline f={fx} top={6} /> : <div className="muted">Loading…</div>}
          </Card>
          <Card title="How this is measured" sub="passive, so read it as evidence rather than proof">
            <div className="stack" style={{ gap: 8, fontSize: 13 }}>
              <div><b>Fix released</b> — the CVE record's references that the vendor (CNA) or CISA tagged <i>patch</i>, <i>vendor-advisory</i> or <i>mitigation</i>, fixed versions in the record, or the vendor advisories CISA cites in KEV. Re-checked every 14 days until a patch appears.</div>
              <div><b>Applied</b> — the organisation's own internet-facing hosts no longer report the CVE on a later scan (Shodan InternetDB). That means patched <i>or</i> the host was removed; AEGIS cannot see inside the network, and InternetDB infers versions from banners.</div>
              <div className="muted" style={{ fontSize: 12 }}>Each still-exposed organisation also has an action here with its due date; closing the exposure closes the action as verified.</div>
            </div>
          </Card>
        </div>
        <Card title="Every exploited CVE on a monitored organisation's hosts" sub="vendor fix, who still exposes it, who no longer does · click a CVE for its card, an organisation for its actions" className="flush">
          <div style={{ padding: '4px 8px 10px' }}>{fx ? <FixTable rows={fx.cves} /> : null}</div>
        </Card>
      </section>

      <SectionLabel>Action queue · change a status inline; expand a row for the playbook and history</SectionLabel>
      <div className="filters">
        <Seg options={[{ id: '', label: 'All levels' }, { id: 'critical', label: 'Critical' }, { id: 'high', label: 'High' }, { id: 'medium', label: 'Medium' }]} value={level as any} onChange={setLevel as any} />
        <select className="txt" value={owner} onChange={e => setOwner(e.target.value)}><option value="">All owners</option>{(q?.owner_roles || []).map((o: string) => <option key={o}>{o}</option>)}</select>
        <select className="txt" value={status} onChange={e => setStatus(e.target.value)}><option value="">Open (new, acknowledged, in progress)</option>
          {Object.entries(STATUS_LABEL).map(([id, l]) => <option key={id} value={id}>{l}</option>)}</select>
        <label className="row" style={{ gap: 6, fontSize: 13 }}><input type="checkbox" checked={overdue} onChange={e => setOverdue(e.target.checked)} />Overdue only</label>
        <span className="muted" style={{ fontSize: 12 }}>{q ? `${q.total.toLocaleString()} actions` : ''}</span>
      </div>
      <Card className="flush">
        {!q ? <div className="muted" style={{ padding: 16 }}>Loading actions…</div> : !q.actions.length ? <Empty>No actions match.</Empty>
          : <div style={{ padding: '4px 8px 10px' }}><ActionTable rows={q.actions} onChanged={() => refetch()} /></div>}
      </Card>
      <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>
        Playbooks: {pv.coverage.with_playbook} of {pv.coverage.rules} organisation rules{pv.coverage.missing.length ? ` (missing: ${pv.coverage.missing.join(', ')})` : ' — every rule has one'}. Control references are indicative.
      </div>

      <PageSources cats={['Attack surface', 'Vulnerabilities', 'Dark web']} note="Controls come from the passive surface scan (DNS over HTTPS) and the daily hardening check (RDAP, DKIM, name servers). Closure is verified by re-observation, never by self-attestation alone." />
    </div>
  )
}
