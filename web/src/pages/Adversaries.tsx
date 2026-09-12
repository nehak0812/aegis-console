import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { motion } from 'motion/react'
import { Search, ExternalLink } from 'lucide-react'
import { useApi, qs } from '../lib/api'
import { Gloss } from '../lib/glossary'
import { Card, Empty, SourceLink, When, Seg, Table, Stat } from '../components/ui'
import { HBar } from '../components/charts'
import WorldMap from '../components/WorldMap'
import { countryName, day } from '../lib/format'

const KIND: Record<string, string> = { apt: 'State-nexus / APT', ecrime: 'eCrime', ransomware: 'Ransomware / extortion', hacktivist: 'Hacktivist' }

function Detail({ id }: { id: string }) {
  const nav = useNavigate()
  const { data } = useApi<any>(`/actors/${id}`, 300)
  if (!data) return <Card><div className="muted">Loading…</div></Card>
  const cs = data.cs_targets || {}
  const vc = Object.fromEntries(Object.entries(data.victim_countries || {}).filter(([k]) => k !== '—')) as Record<string, number>
  return (
    <motion.div key={id} initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} className="stack" style={{ gap: 14 }}>
      <Card>
        <div className="row wrap" style={{ gap: 8 }}>
          <span className="pill accent">{KIND[data.kind] || data.kind}</span>
          {data.origin && <span className="pill">Origin: {countryName(data.origin)}</span>}
          {data.motivation && <span className="pill">{data.motivation}</span>}
          {data.attack_id && <a className="pill btn" href={`https://attack.mitre.org/groups/${data.attack_id}/`} target="_blank" rel="noreferrer">MITRE {data.attack_id} <ExternalLink size={10} /></a>}
          {data.cs_url && <a className="pill btn" href={data.cs_url} target="_blank" rel="noreferrer">CrowdStrike profile <ExternalLink size={10} /></a>}
        </div>
        <h2 style={{ margin: '10px 0 4px' }}>{data.name}{data.crowdstrike && data.crowdstrike !== data.name && <span className="muted" style={{ fontSize: 15, fontWeight: 500 }}> · CrowdStrike: {data.crowdstrike}</span>}</h2>
        {data.aliases?.length > 0 && <div className="muted" style={{ fontSize: 12.5 }}>Also known as: {data.aliases.slice(0, 18).join(', ')}</div>}
        {data.description && <p className="ink2" style={{ marginBottom: 0 }}>{data.description}</p>}
        <div className="row wrap" style={{ gap: 6, marginTop: 10 }}>{(data.refs || []).slice(0, 5).map((r: string) => <SourceLink key={r} url={r} />)}</div>
      </Card>
      <div className="grid g3">
        <Stat label="Leak-site victims (tracked)" value={data.victims.length} hint="all time in store" />
        <Stat label="Reporting mentions" value={data.items.length} hint="last 120 days" />
        <Stat label="Publishers reporting" value={Object.keys(data.publishers).length} hint="consensus across sources" />
      </div>
      {(cs.countries?.length || cs.industries?.length || data.sectors?.length || data.countries?.length) ? (
        <Card title="Who it targets" sub="CrowdStrike Adversary Universe (public) · MISP / CFR attribution">
          <div className="row wrap" style={{ gap: 6 }}>
            {(cs.industries || []).map((i: string) => <span key={i} className="pill accent">{i}</span>)}
            {(data.sectors || []).map((s: string) => <span key={s} className="pill">{s}</span>)}
          </div>
          <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>
            {(cs.countries || []).map((c: string) => <span key={c} className="pill">{countryName(c)}</span>)}
            {(data.countries || []).slice(0, 20).map((c: string) => <span key={c} className="pill">{c}</span>)}
          </div>
        </Card>) : null}
      {data.victims.length > 0 && (
        <div className="grid g2">
          <Card title="Victims by sector"><HBar data={Object.entries(data.victim_sectors).map(([s, n]) => ({ s, n })).sort((a: any, b: any) => b.n - a.n).slice(0, 10)} label="s" value="n" /></Card>
          <Card title="Victims by country" className="flush"><div style={{ padding: 12 }}><WorldMap choropleth={vc} height={230} /></div></Card>
        </div>)}
      {(data.tools?.length || data.techniques?.length) ? (
        <Card title="Tools & techniques" sub="MITRE ATT&CK">
          <div className="row wrap" style={{ gap: 6 }}>{(data.tools || []).map((t: string) => <span key={t} className="pill accent">{t}</span>)}</div>
          <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>{(data.techniques || []).slice(0, 40).map((t: string) => <a key={t} className="pill btn mono" href={`https://attack.mitre.org/techniques/${t.split(' ')[0].replace('.', '/')}/`} target="_blank" rel="noreferrer">{t}</a>)}</div>
        </Card>) : null}
      {data.victims.length > 0 && (
        <Card title="Latest victims" sub="from leak-site trackers">
          <Table rows={data.victims} max={60} onRow={(v: any) => v.org_id && nav(`/orgs/${v.org_id}`)} cols={[
            { key: 'published', label: 'Listed', render: (v: any) => day(v.published) }, { key: 'victim', label: 'Victim', render: (v: any) => <>{v.victim}{v.org_name && <span className="pill accent" style={{ marginLeft: 6 }}>monitored</span>}</> },
            { key: 'country', label: 'Country', render: (v: any) => countryName(v.country) }, { key: 'sector', label: 'Sector' }, { key: 'url', label: '', render: (v: any) => <SourceLink url={v.url} /> }]} />
        </Card>)}
      <Card title="Who is reporting on this actor">
        {data.items.length ? (
          <div className="grid g-main-side">
            <div className="feed">{data.items.slice(0, 25).map((i: any) => (
              <div key={i.id} className="feed-item"><span className="pill">{i.pub_type}</span><div><div className="t">{i.title}</div><div className="m"><span>{i.publisher}</span><When ts={i.published} /></div></div><SourceLink url={i.url} /></div>))}</div>
            <HBar data={Object.entries(data.publishers).map(([p, n]) => ({ p, n })).sort((a: any, b: any) => b.n - a.n).slice(0, 10)} label="p" value="n" />
          </div>) : <Empty>No mentions in the collected reporting.</Empty>}
      </Card>
    </motion.div>
  )
}

export default function Adversaries() {
  const { id } = useParams()
  const nav = useNavigate()
  const [kind, setKind] = useState('')
  const [q, setQ] = useState('')
  const { data } = useApi<any>(`/actors${qs({ kind, q: q.length > 1 ? q : '' })}`, 300)
  const rows = data?.actors || []
  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">Adversaries</div>
          <h2>Who is active, what they target, and who is reporting it</h2>
          <p><Gloss>One alias index across naming schemes — CrowdStrike (BEAR, PANDA, KITTEN, CHOLLIMA, SPIDER, JACKAL…), Microsoft weather names, MITRE ATT&CK IDs and MISP — ranked by live activity: reporting mentions and leak-site victims.</Gloss></p>
        </div>
      </div>
      <div className="filters">
        <Seg options={[{ id: '', label: 'All' }, { id: 'ransomware', label: 'Ransomware' }, { id: 'apt', label: 'State-nexus' }, { id: 'ecrime', label: 'eCrime' }, { id: 'hacktivist', label: 'Hacktivist' }]} value={kind as any} onChange={setKind as any} />
        <div className="search" style={{ maxWidth: 280 }}><Search size={14} /><input value={q} onChange={e => setQ(e.target.value)} placeholder="name, alias, CrowdStrike name…" /></div>
        {data && <span className="muted" style={{ fontSize: 12 }}>{data.total} actors</span>}
      </div>
      <div className="grid g-side-main" style={{ alignItems: 'start' }}>
        <Card className="flush">
          <div style={{ maxHeight: 'calc(100vh - 240px)', overflowY: 'auto', padding: '4px 12px' }}>
            {rows.map((a: any) => (
              <div key={a.id} className="feed-item clickable" onClick={() => nav(`/adversaries/${a.id}`)}
                style={{ gridTemplateColumns: '1fr auto', background: a.id === id ? 'var(--accent-wash)' : undefined, borderRadius: 8, padding: '9px 8px' }}>
                <div>
                  <div className="t">{a.name}</div>
                  <div className="m"><span>{KIND[a.kind]}</span>{a.crowdstrike && a.crowdstrike !== a.name && <span>{a.crowdstrike}</span>}{a.origin && <span>{countryName(a.origin)}</span>}</div>
                </div>
                <div style={{ textAlign: 'right', fontSize: 12 }}>
                  {a.victims_30d > 0 && <div><b>{a.victims_30d}</b> <span className="muted">victims</span></div>}
                  {a.mentions_30d > 0 && <div><b>{a.mentions_30d}</b> <span className="muted">mentions</span></div>}
                </div>
              </div>))}
          </div>
        </Card>
        {id ? <Detail id={id} /> : (
          <div className="stack" style={{ gap: 14 }}>
            <div className="grid g2">
              <Card title="Most active now" sub="reporting mentions + leak-site victims, 30 days">
                <HBar data={rows.filter((r: any) => r.activity > 0).slice(0, 14).map((r: any) => ({ name: r.name, n: r.activity, id: r.id }))} label="name" value="n" onClick={d => nav(`/adversaries/${d.id}`)} />
              </Card>
              <Card title="By attributed origin" sub="MISP country, or CrowdStrike / Microsoft naming convention">
                <HBar data={Object.entries(data?.origins || {}).filter(([k]) => k !== 'Unknown').map(([k, n]) => ({ k: countryName(k), n })).sort((a: any, b: any) => b.n - a.n).slice(0, 12)} label="k" value="n" />
              </Card>
            </div>
            <Card title="Select an actor" sub="to see targets, victims, tools, techniques and who is reporting on it"><Empty>Pick from the list, or search by any vendor's name for the group.</Empty></Card>
          </div>)}
      </div>
    </div>
  )
}
