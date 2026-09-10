import { useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Plus, Search } from 'lucide-react'
import { useApi, qs, api } from '../lib/api'
import { Card, Sev, SevBar, Table, Seg, Empty, When } from '../components/ui'
import WorldMap from '../components/WorldMap'
import { HBar } from '../components/charts'
import { SEV_COLOR } from '../lib/chartTheme'
import { countryName } from '../lib/format'

function AddOrg({ onDone }: { onDone: (id: string) => void }) {
  const [f, setF] = useState({ name: '', domain: '', country: '', sector: '' })
  const [err, setErr] = useState('')
  const submit = async () => {
    setErr('')
    try {
      const r = await api<{ id: string }>('/orgs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(f) })
      onDone(r.id)
    } catch (e: any) { setErr(String(e.message || e)) }
  }
  return (
    <Card title="Add an organisation to monitor" sub="a passive scan starts immediately (public DNS, CT, indexes only)">
      <div className="row wrap" style={{ gap: 8 }}>
        <input className="txt" placeholder="Organisation name" value={f.name} onChange={e => setF({ ...f, name: e.target.value })} />
        <input className="txt" placeholder="Primary domain e.g. example.com" value={f.domain} onChange={e => setF({ ...f, domain: e.target.value })} />
        <input className="txt" placeholder="Country (ISO-2)" style={{ width: 120 }} value={f.country} onChange={e => setF({ ...f, country: e.target.value })} />
        <input className="txt" placeholder="Sector (optional)" value={f.sector} onChange={e => setF({ ...f, sector: e.target.value })} />
        <button className="btn primary" onClick={submit}><Plus size={14} />Add & scan</button>
        {err && <span style={{ color: SEV_COLOR.critical }}>{err}</span>}
      </div>
    </Card>
  )
}

export default function Orgs() {
  const nav = useNavigate()
  const [sp] = useSearchParams()
  const [q, setQ] = useState('')
  const [level, setLevel] = useState(sp.get('level') || '')
  const [sector, setSector] = useState('')
  const [country, setCountry] = useState('')
  const [index, setIndex] = useState('')
  const [adding, setAdding] = useState(false)
  const { data } = useApi<any>(`/orgs${qs({ q: q.length > 1 ? q : '', level, sector, country, index })}`, 120)
  const all = useApi<any>('/orgs', 300).data
  const rows = data?.orgs || []
  const sectors = useMemo(() => Object.keys(all?.facets?.sector || {}).sort(), [all])
  const countries = useMemo(() => Object.entries(all?.facets?.country || {}).sort((a: any, b: any) => b[1] - a[1]).map(([c]) => c), [all])
  const lv = data?.facets?.level || {}

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">Organisations</div>
          <h2>The monitored universe</h2>
          <p>S&P 500, FTSE 100, DAX 40, CAC 40 and EURO STOXX 50 constituents from public registries, plus organisations you add. Each is assessed across twelve categories; its level is the most severe active finding.</p>
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
            <HBar data={Object.entries(data?.facets?.sector || {}).map(([s, n]) => ({ s, n })).sort((a: any, b: any) => b.n - a.n).slice(0, 8)} label="s" value="n" onClick={d => setSector(d.s)} />
          </div>
        </Card>
      </div>

      <div className="filters">
        <div className="search" style={{ maxWidth: 280 }}><Search size={14} /><input value={q} onChange={e => setQ(e.target.value)} placeholder="name, ticker, domain…" /></div>
        <Seg options={[{ id: '', label: 'All' }, { id: 'critical', label: 'Critical' }, { id: 'high', label: 'High' }, { id: 'medium', label: 'Medium' }]} value={level as any} onChange={setLevel as any} />
        <select className="txt" value={sector} onChange={e => setSector(e.target.value)}><option value="">All sectors</option>{sectors.map(s => <option key={s}>{s}</option>)}</select>
        <select className="txt" value={country} onChange={e => setCountry(e.target.value)}><option value="">All countries</option>{countries.map(c => <option key={c} value={c}>{countryName(c)}</option>)}</select>
        <select className="txt" value={index} onChange={e => setIndex(e.target.value)}><option value="">All lists</option>{['S&P 500', 'FTSE 100', 'DAX 40', 'CAC 40', 'EURO STOXX 50', 'Added by analyst'].map(i => <option key={i}>{i}</option>)}</select>
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
