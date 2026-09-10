import { Fragment, useState } from 'react'
import { CheckCircle2, AlertTriangle, PauseCircle, Loader2, Clock, Play, ChevronRight, ChevronDown } from 'lucide-react'
import { useApi, api } from '../lib/api'
import { Gloss, gloss } from '../lib/glossary'
import { Card, Stat, Sev, SourceLink, When, Tabs, Table } from '../components/ui'
import { Spark } from '../components/charts'
import { compact } from '../lib/format'

const ST: Record<string, any> = {
  OK: [CheckCircle2, 'var(--good)', 'Live'], EMPTY: [Clock, 'var(--medium)', 'No new data'], DEGRADED: [AlertTriangle, 'var(--high)', 'Degraded'],
  DISABLED: [PauseCircle, 'var(--muted)', 'Disabled'], RUNNING: [Loader2, 'var(--accent)', 'Collecting'], PENDING: [Clock, 'var(--muted)', 'Queued'],
}

function Status({ s }: { s: string }) {
  const [I, c, l] = ST[s] || ST.PENDING
  return <span className="row" style={{ gap: 6, color: c, fontSize: 12.5, fontWeight: 600 }}><I size={14} className={s === 'RUNNING' ? 'spin' : ''} />{l}</span>
}

export default function Sources() {
  const { data, refetch } = useApi<any>('/sources', 30)
  const { data: method } = useApi<any>('/method', 3600)
  const [tab, setTab] = useState<'sources' | 'rules' | 'linkage' | 'bitsight'>('sources')
  const [open, setOpen] = useState<string | null>(null)
  if (!data) return <div className="muted">Loading sources…</div>
  const cats = Array.from(new Set((data.sources as any[]).map(s => s.category)))
  const run = async (id: string) => { await api(`/sources/${id}/run`, { method: 'POST' }); setTimeout(() => refetch(), 1500) }
  const c = data.counts

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">Sources & method</div>
          <h2>Where every record comes from, and how levels are decided</h2>
          <p><Gloss>Only free, open sources. Collection is passive: public indexes, registries, feeds and DNS — never a scan or a probe of an organisation, never a purchase, never a credential. Each source runs on its own cadence; a failing source is marked degraded rather than filled with anything invented.</Gloss></p>
        </div>
      </div>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', marginBottom: 14 }}>
        {[['Organisations', c.orgs], ['Reporting items', c.items], ['Dark-web records', c.leaks], ['Vulnerabilities', c.vulns], ['Threat actors', c.actors], ['Incidents', c.incidents], ['Findings', c.findings], ['Assets', c.assets], ['Provider links', c.dependencies]].map(([l, v]) => <Stat key={l as string} label={l as string} value={compact(v as number)} />)}
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[{ id: 'sources', label: 'Sources', count: data.sources.length }, { id: 'rules', label: 'Rating rules' }, { id: 'linkage', label: 'Linkage & themes' }, { id: 'bitsight', label: 'Bitsight-style coverage' }]} />

      {tab === 'sources' && cats.map(cat => (
        <Card key={cat} title={cat} className="flush" >
          <div className="tbl-wrap" style={{ padding: '0 8px 8px' }}>
            <table className="tbl">
              <thead><tr><th style={{ width: 24 }} /><th>Source</th><th>Status</th><th>Last success</th><th className="num">Last run</th><th>Runs (7d)</th><th>Cadence</th><th>Licence</th><th /></tr></thead>
              <tbody>
                {(data.sources as any[]).filter(s => s.category === cat).map(s => (
                  <Fragment key={s.id}>
                    <tr className="click" onClick={() => setOpen(open === s.id ? null : s.id)}>
                      <td>{open === s.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</td>
                      <td><b>{gloss(s.name)}</b><div className="muted" style={{ fontSize: 12 }}>{s.publisher}</div></td>
                      <td><Status s={s.status} /></td>
                      <td>{s.last_ok ? <When ts={s.last_ok} /> : <span className="muted">—</span>}</td>
                      <td className="num">{compact(s.items_last_run)}</td>
                      <td style={{ width: 120 }}>{s.runs.length > 1 ? <Spark data={s.runs} k="n" /> : <span className="muted">—</span>}</td>
                      <td className="muted">{s.cadence_min >= 1440 ? `${Math.round(s.cadence_min / 1440)}d` : s.cadence_min >= 60 ? `${Math.round(s.cadence_min / 60)}h` : `${s.cadence_min}m`}</td>
                      <td className="muted" style={{ fontSize: 12, maxWidth: 220 }}>{s.licence}</td>
                      <td>{s.status !== 'DISABLED' && <button className="btn" onClick={e => { e.stopPropagation(); run(s.id) }}><Play size={12} />Run</button>}</td>
                    </tr>
                    {open === s.id && (
                      <tr><td /><td colSpan={8}>
                        <div className="stack" style={{ padding: '4px 0 10px' }}>
                          <div className="ink2">{gloss(s.notes)}</div>
                          <div className="row wrap" style={{ gap: 10 }}><SourceLink url={s.homepage} label="Homepage" />{s.url && <SourceLink url={s.url} label="Endpoint" />}<span className="muted">access: {s.access}</span></div>
                          {s.last_error && <div className="why" style={{ borderColor: 'var(--high)' }}><b>Last error:</b> {s.last_error}</div>}
                          {s.feed_health?.length > 0 && (
                            <Table rows={s.feed_health} cols={[{ key: 'publisher', label: 'Feed', render: (f: any) => <SourceLink url={f.url} label={f.publisher} /> },
                              { key: 'ok', label: 'Status', render: (f: any) => f.ok ? <Status s="OK" /> : <span title={f.error}><Status s="DEGRADED" /></span> },
                              { key: 'items', label: 'Items', num: true }, { key: 'at', label: 'Checked', render: (f: any) => <When ts={f.at} /> }]} />)}
                          {!s.feed_health?.length && s.feeds?.length > 0 && <div className="row wrap" style={{ gap: 8 }}>{s.feeds.map((f: any) => <SourceLink key={f.url} url={f.url} label={f.publisher} />)}</div>}
                        </div>
                      </td></tr>)}
                  </Fragment>))}
              </tbody>
            </table>
          </div>
        </Card>
      )).reduce((acc: any[], el, i) => [...acc, el, <div key={'g' + i} style={{ height: 14 }} />], [])}

      {tab === 'rules' && method && (
        <div className="stack" style={{ gap: 14 }}>
          <Card title="Four levels, no scores" sub="every level is assigned by exactly one of these rules; hover any level in the console to see its rule">
            <div className="row wrap" style={{ gap: 12 }}>{['critical', 'high', 'medium', 'low'].map(l => <Sev key={l} level={l} />)}<span className="muted">An organisation's level is its most severe active finding (Low findings are inventory and context).</span></div>
          </Card>
          {['organisation', 'vulnerability', 'incident'].map(a => (
            <Card key={a} title={`${a[0].toUpperCase() + a.slice(1)} rules`}>
              <Table rows={method.rules.filter((r: any) => r.applies_to === a)} max={100} cols={[
                { key: 'level', label: 'Level', render: (r: any) => <Sev level={r.level} />, sort: (r: any) => ['critical', 'high', 'medium', 'low'].indexOf(r.level) },
                { key: 'id', label: 'Rule', render: (r: any) => <span className="mono">{r.id}</span> }, { key: 'rule', label: 'Condition' }]} initialSort={['level', 'asc']} />
            </Card>))}
        </div>
      )}

      {tab === 'linkage' && method && (
        <div className="grid g2">
          <Card title="How incidents reach organisations" sub="five explainable linkage types">
            <Table rows={Object.entries(method.link_types).map(([k, v]) => ({ k, v }))} cols={[{ key: 'k', label: 'Type', render: (r: any) => <span className="mono">{r.k}</span> }, { key: 'v', label: 'Meaning' }]} />
            <div className="muted" style={{ fontSize: 12, marginTop: 10 }}>Victim and exposed-CVE links are Critical; subsidiary, provider-breach and exposed-hostname links are High; provider outages Medium; sector targeting Low.</div>
          </Card>
          <Card title="Theme dictionary" sub="the exact patterns used to tag reporting">
            <div style={{ maxHeight: 520, overflowY: 'auto' }}>
              <Table rows={method.themes} max={200} cols={[{ key: 'family', label: 'Family' }, { key: 'theme', label: 'Theme' }, { key: 'patterns', label: 'Patterns', render: (t: any) => <span className="mono muted" style={{ fontSize: 11 }}>{t.patterns.join(' | ')}</span> }]} />
            </div>
          </Card>
        </div>
      )}

      {tab === 'bitsight' && method && (
        <Card title="Bitsight risk vectors, approximated with free passive sources" sub="what AEGIS can and cannot assess — gaps are stated, never filled">
          <Table rows={method.bitsight_mapping} cols={[{ key: 'group', label: 'Bitsight group' }, { key: 'vector', label: 'Risk vector' }, { key: 'aegis', label: 'AEGIS category' }, { key: 'sources', label: 'Free sources' }, { key: 'strength', label: 'Coverage' }]} />
        </Card>
      )}
    </div>
  )
}
