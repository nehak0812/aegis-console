import { useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Plus, Search, Download } from 'lucide-react'
import { useApi, qs, api } from '../lib/api'
import { Gloss } from '../lib/glossary'
import { Card, Sev, SevBar, Table, Seg, Empty, When, MultiSelect } from '../components/ui'
import WorldMap from '../components/WorldMap'
import { HBar } from '../components/charts'
import { SEV_COLOR } from '../lib/chartTheme'
import { countryName, COUNTRY } from '../lib/format'

function AddOrg({ onDone }: { onDone: (id: string) => void }) {
  const [f, setF] = useState({ name: '', domain: '', country: '', sector: '' })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  // the domain is what the passive scan resolves, so the server rejects the org without one
  const ready = f.name.trim().length > 1 && f.domain.trim().includes('.')
  const submit = async () => {
    if (!ready || busy) return
    setErr(''); setBusy(true)
    try {
      const r = await api<{ id: string }>('/orgs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(f) })
      onDone(r.id)
    } catch (e: any) { setErr(String(e.message || e)) } finally { setBusy(false) }
  }
  return (
    <Card title="Add an organisation to monitor" sub="a passive scan starts immediately (public DNS, CT, indexes only)">
      <div className="row wrap" style={{ gap: 8 }}>
        <input className="txt" placeholder="Organisation name" style={{ minWidth: 200 }} value={f.name}
          onChange={e => setF({ ...f, name: e.target.value })} onKeyDown={e => e.key === 'Enter' && submit()} />
        <input className="txt" placeholder="Primary domain — required, e.g. ril.com" style={{ minWidth: 260 }} value={f.domain}
          onChange={e => setF({ ...f, domain: e.target.value })} onKeyDown={e => e.key === 'Enter' && submit()} />
        <input className="txt" list="country-options" placeholder="Country e.g. India or IN" style={{ minWidth: 170 }} value={f.country}
          onChange={e => setF({ ...f, country: e.target.value })} onKeyDown={e => e.key === 'Enter' && submit()} />
        <datalist id="country-options">{Object.entries(COUNTRY).map(([a2, n]) => <option key={a2} value={n} />)}</datalist>
        <input className="txt" placeholder="Sector (optional)" value={f.sector}
          onChange={e => setF({ ...f, sector: e.target.value })} onKeyDown={e => e.key === 'Enter' && submit()} />
        <button className="btn primary" disabled={!ready || busy} onClick={submit}><Plus size={14} />{busy ? 'Adding…' : 'Add & scan'}</button>
      </div>
      {(err || !ready) && (
        <div style={{ marginTop: 8, fontSize: 12, color: err ? SEV_COLOR.critical : 'var(--muted)' }}>
          {err || 'A name and a primary domain are required — the domain is what the passive scan looks up.'}
        </div>
      )}
    </Card>
  )
}

export default function Orgs() {
  const nav = useNavigate()
  const [sp] = useSearchParams()
  const [q, setQ] = useState('')
  const [level, setLevel] = useState(sp.get('level') || '')
  const [sector, setSector] = useState<string[]>([])
  const [country, setCountry] = useState<string[]>([])
  const [index, setIndex] = useState<string[]>([])
  const [adding, setAdding] = useState(false)
  // one filter set drives the table and the spreadsheet, so an export always matches what is on screen
  const filters = { q: q.length > 1 ? q : '', level, sector, country, index }
  const { data } = useApi<any>(`/orgs${qs(filters)}`, 120)
  const all = useApi<any>('/orgs', 300).data
  const rows = data?.orgs || []
  // options come from the unfiltered universe, so narrowing one filter never hides the rest
  const sectorOpts = useMemo(() => Object.entries(all?.facets?.sector || {})
    .sort((a, b) => a[0].localeCompare(b[0])).map(([id, count]) => ({ id, count: count as number })), [all])
  const countryOpts = useMemo(() => Object.entries(all?.facets?.country || {})
    .sort((a: any, b: any) => b[1] - a[1]).map(([id, count]) => ({ id, label: countryName(id), count: count as number })), [all])
  const indexOpts = ['S&P 500', 'FTSE 100', 'DAX 40', 'CAC 40', 'EURO STOXX 50', 'Added by analyst'].map(id => ({ id }))
  const chosen = sector.length + country.length + index.length + (level ? 1 : 0) + (q.length > 1 ? 1 : 0)
  const lv = data?.facets?.level || {}

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">Organisations</div>
          <h2>The monitored universe</h2>
          <p><Gloss>S&P 500, FTSE 100, DAX 40, CAC 40 and EURO STOXX 50 constituents from public registries, plus organisations you add. Each is assessed across twelve categories; its level is the most severe active finding.</Gloss></p>
        </div>
        <button className="btn" style={{ marginLeft: 'auto' }} onClick={() => setAdding(a => !a)}><Plus size={14} />Add organisation</button>
      </div>
      {adding && <div style={{ marginBottom: 14 }}><AddOrg onDone={id => nav(`/orgs/${id}`)} /></div>}

      <div className="grid g-main-side" style={{ marginBottom: 14 }}>
        <Card title="Where they are" sub="HQ location · colour = current level · click to open" className="flush">
          <div style={{ padding: '0 16px 16px' }}>
            <WorldMap zoomable points={rows.filter((r: any) => r.lat != null).map((r: any) => ({ id: r.id, lat: r.lat, lon: r.lon, level: r.level || 'low', label: r.name, sub: `${r.sector || ''} · ${r.level || 'unassessed'}`, onClick: () => nav(`/orgs/${r.id}`), pulse: r.level === 'critical' }))} />
          </div>
        </Card>
        <Card title="Current levels" sub={`${rows.length} organisations in view`}>
          <div className="stack" style={{ gap: 10 }}>
            {['critical', 'high', 'medium', 'low', 'clear', 'queued'].map(l => (
              <div key={l} className="row clickable" style={{ padding: '6px 8px', borderRadius: 8, background: level === l ? 'var(--accent-wash)' : undefined }} onClick={() => setLevel(level === l ? '' : l)}>
                {l === 'clear' ? <span className="pill">No findings</span> : l === 'queued' ? <span className="pill">Surface scan queued</span> : <Sev level={l} />}
                <div style={{ flex: 1, height: 8, background: 'var(--hair)', borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ width: `${(100 * (lv[l] || 0)) / Math.max(1, rows.length)}%`, height: '100%', background: SEV_COLOR[l] || 'var(--hair-2)', borderRadius: 4, transition: 'width .6s' }} />
                </div>
                <b style={{ width: 36, textAlign: 'right' }}>{lv[l] || 0}</b>
              </div>
            ))}
            <div className="muted" style={{ fontSize: 12 }}>By sector</div>
            <HBar data={Object.entries(data?.facets?.sector || {}).map(([s, n]) => ({ s, n })).sort((a: any, b: any) => b.n - a.n).slice(0, 8)} label="s" value="n" onClick={d => setSector([d.s])} />
          </div>
        </Card>
      </div>

      <div className="filters">
        <div className="search" style={{ maxWidth: 280 }}><Search size={14} /><input value={q} onChange={e => setQ(e.target.value)} placeholder="name, ticker, domain…" /></div>
        <Seg options={[{ id: '', label: 'All' }, { id: 'critical', label: 'Critical' }, { id: 'high', label: 'High' }, { id: 'medium', label: 'Medium' }]} value={level as any} onChange={setLevel as any} />
        <MultiSelect label="All sectors" options={sectorOpts} value={sector} onChange={setSector} width={200} />
        <MultiSelect label="All countries" options={countryOpts} value={country} onChange={setCountry} width={200} />
        <MultiSelect label="All lists" options={indexOpts} value={index} onChange={setIndex} width={185} />
        {chosen > 1 && (
          <button className="btn" onClick={() => { setQ(''); setLevel(''); setSector([]); setCountry([]); setIndex([]) }}>Reset filters</button>
        )}
        <a className="btn" style={{ marginLeft: 'auto' }} href={`/api/orgs/export${qs(filters)}`}
          title={`Download ${rows.length} organisation${rows.length === 1 ? '' : 's'} as an Excel workbook`}>
          <Download size={14} />Excel ({rows.length})
        </a>
      </div>
      <Card className="flush">
        {!rows.length ? <Empty>No organisations match.</Empty> : (
          <Table rows={rows} onRow={(r: any) => nav(`/orgs/${r.id}`)} initialSort={['level', 'asc']} max={700}
            cols={[
              { key: 'name', label: 'Organisation', render: (r: any) => <><b>{r.name}</b> {r.ticker && <span className="muted mono">{r.ticker}</span>}<div className="muted" style={{ fontSize: 12 }}>{r.domain || 'no domain on record'}</div></> },
              { key: 'level', label: 'Level', render: (r: any) => r.level ? <Sev level={r.level} /> : <span className="pill">{r.state === 'clear' ? 'No findings' : 'Scan queued'}</span>, sort: (r: any) => (r.level ? ['critical', 'high', 'medium', 'low'].indexOf(r.level) : r.state === 'clear' ? 8 : 9) },
              { key: 'counts', label: 'Findings', render: (r: any) => <div style={{ width: 130 }}><SevBar counts={r.counts} /></div>, sort: (r: any) => -((r.counts.critical || 0) * 1000 + (r.counts.high || 0) * 10 + (r.counts.medium || 0)) },
              { key: 'incidents_30d', label: 'Linked incidents', num: true },
              { key: 'sector', label: 'Sector', render: (r: any) => <span className="ink2">{r.sector || '—'}</span> },
              { key: 'country', label: 'Country', render: (r: any) => countryName(r.country) },
              { key: 'indices', label: 'Lists', render: (r: any) => <span className="muted" style={{ fontSize: 12 }}>{(r.indices || []).join(', ')}</span> },
              { key: 'deep_scanned', label: 'Surface scan', render: (r: any) => r.deep_scanned ? <When ts={r.deep_scanned} /> : <span className="muted">queued</span> },
            ]} />
        )}
      </Card>
    </div>
  )
}
