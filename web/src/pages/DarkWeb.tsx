import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ResponsiveStream } from '@nivo/stream'
import { useApi } from '../lib/api'
import { useRange } from '../App'
import { PageSources, SectionLabel } from '../components/ui'
import { Card, Stat, Table, Empty, SourceLink, Tabs, When, Legend } from '../components/ui'
import { HBar } from '../components/charts'
import WorldMap from '../components/WorldMap'
import { SERIES, NEUTRAL, nivoTheme } from '../lib/chartTheme'
import { compact, countryName, day } from '../lib/format'

const CLAIM: Record<string, string> = { access: 'Initial access sale', data: 'Data sale / leak', credentials: 'Credentials', ddos: 'DDoS claim', extortion: 'Extortion' }

export default function DarkWeb() {
  const { range } = useRange()
  const nav = useNavigate()
  const [tab, setTab] = useState<'overview' | 'leaks' | 'claims' | 'creds' | 'hacktivist' | 'chatter' | 'catalogue'>('overview')
  const { data } = useApi<any>(`/darkweb?days=${range}`, 120)
  const STREAM_COLORS = [...SERIES.slice(0, 7), NEUTRAL]  // top 7 groups + neutral "other"; read at render so the theme applies
  if (!data) return <div className="muted">Loading dark-web intelligence…</div>
  const c = data.counts
  const orgLink = (r: any) => r.org_id ? <a className="pill btn accent" onClick={() => nav(`/orgs/${r.org_id}`)}>{r.org_name}</a> : null

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">Deep & dark web · forums · chatter</div>
          <h2>What is being claimed, sold, leaked and plotted</h2>
          <p>Metadata only, from reputable third-party trackers — leak-site monitors, outlets that report forum and market posts, infostealer and breach catalogues, hacktivist target lists and open community chatter. We never visit .onion sites, never store credentials, and label claims as unverified.</p>
        </div>
      </div>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(6, minmax(0,1fr))', marginBottom: 14 }}>
        <Stat label={`Leak-site listings · ${range}d`} value={compact(c.leaksite)} hint={`${c.groups} active groups`} onClick={() => setTab('leaks')} />
        <Stat label={`Monitored orgs listed · ${range}d`} value={c.watch_listed} hint="on a leak site in the window" onClick={() => setTab('leaks')} />
        <Stat label={`Forum & market claims · ${range}d`} value={c.forum} hint="access, data, credentials" onClick={() => setTab('claims')} />
        <Stat label="Infostealer-exposed orgs · now" value={c.stealer_orgs} hint={`of ${c.stealer_checked} checked`} onClick={() => setTab('creds')} />
        <Stat label={`DDoS target domains · ${range}d`} value={c.ddos} hint="NoName057(16) DDoSia" onClick={() => setTab('hacktivist')} />
        <Stat label="Sources catalogued · now" value={compact(data.catalogue_total)} hint="forums, markets, channels" onClick={() => setTab('catalogue')} />
      </div>
      <SectionLabel>Visual overview, then each record type</SectionLabel>
      <Tabs value={tab} onChange={setTab} tabs={[{ id: 'overview', label: 'Overview' }, { id: 'leaks', label: 'Leak sites', count: c.leaksite }, { id: 'claims', label: 'Forum & market claims', count: c.forum },
        { id: 'creds', label: 'Credentials & breaches' }, { id: 'hacktivist', label: 'Hacktivist targeting', count: c.ddos }, { id: 'chatter', label: 'Chatter' }, { id: 'catalogue', label: 'Source catalogue' }]} />

      {tab === 'overview' && (
        <div className="stack" style={{ gap: 14 }}>
          <Card title="Leak-site activity by group" sub="daily listings · top 7 groups + all others">
            {data.stream.length > 1 ? (
              <>
                <div style={{ height: 280 }}>
                  <ResponsiveStream data={data.stream} keys={data.stream_keys} margin={{ top: 10, right: 10, bottom: 34, left: 40 }} offsetType="none" curve="basis"
                    colors={STREAM_COLORS} fillOpacity={0.85} borderWidth={0} theme={nivoTheme as any} enableGridX={false}
                    axisBottom={{ format: (i: number) => (i % Math.ceil(data.stream.length / 8) === 0 && data.stream[i] ? new Date(data.stream[i].day).toLocaleDateString(undefined, { day: 'numeric', month: 'short' }) : ''), tickSize: 0, tickPadding: 8 }}
                    axisLeft={{ tickSize: 0, tickPadding: 6 }} animate motionConfig="gentle" />
                </div>
                <Legend items={data.stream_keys.map((k: string, i: number) => ({ label: k, color: STREAM_COLORS[i] }))} />
              </>) : <Empty>Collecting…</Empty>}
          </Card>
          <div className="grid g3">
            <Card title="Most active groups" sub="click for the adversary profile"><HBar data={data.groups.slice(0, 12)} label="group" value="n" onClick={d => nav(`/adversaries/rw-${String(d.group).toLowerCase()}`)} /></Card>
            <Card title="Victims by sector"><HBar data={data.sectors.slice(0, 12)} label="sector" value="n" /></Card>
            <Card title="Victims by country" sub="darker = more listings · where the tracker reports a country"><WorldMap choropleth={data.countries} height={250} /></Card>
          </div>
        </div>
      )}

      {tab === 'leaks' && (
        <Card className="flush" title="" >
          <Table rows={data.leaksite} max={400} cols={[
            { key: 'published', label: 'Listed', render: (l: any) => <When ts={l.published} /> },
            { key: 'victim', label: 'Victim', render: (l: any) => <><b>{l.victim}</b>{l.domain && <div className="muted mono" style={{ fontSize: 11 }}>{l.domain}</div>}</> },
            { key: 'org', label: 'Monitored', render: orgLink, sort: (l: any) => (l.org_id ? 0 : 1) },
            { key: 'actor', label: 'Group', render: (l: any) => <a className="pill btn" onClick={() => nav(`/adversaries/rw-${String(l.actor).toLowerCase()}`)}>{l.actor}</a> },
            { key: 'country', label: 'Country', render: (l: any) => countryName(l.country) }, { key: 'sector', label: 'Sector', render: (l: any) => <span className="ink2">{l.sector || '—'}</span> },
            { key: 'src', label: 'Seen by', render: (l: any) => <span className="muted" style={{ fontSize: 12 }}>{(l.extra?.sources || [l.source_id]).join(', ')}</span> },
            { key: 'url', label: '', render: (l: any) => <SourceLink url={l.url} /> }]} />
        </Card>
      )}

      {tab === 'claims' && (
        <div className="grid g-main-side">
          <Card title="Claims reported from forums, markets and Telegram" sub="unverified until confirmed by the organisation · headline + link only">
            <div className="feed">
              {!data.forum.length && <Empty>No claims in this window.</Empty>}
              {data.forum.map((l: any) => (
                <div key={l.id} className="feed-item">
                  <span className="pill">{CLAIM[l.extra?.claim] || 'Claim'}</span>
                  <div><div className="t">{l.title}</div><div className="m"><span>{l.extra?.publisher}</span><When ts={l.published} />{orgLink(l)}</div></div>
                  <SourceLink url={l.url} />
                </div>))}
            </div>
          </Card>
          <Card title="Claim types"><HBar data={Object.entries(data.claims).map(([k, n]) => ({ k: CLAIM[k] || k, n }))} label="k" value="n" />
            <div className="muted" style={{ fontSize: 12, marginTop: 10 }}>Initial-access sales against a monitored organisation in the last 14 days are rated Critical (rule DW-ACCESS-14); data or credential claims in 30 days are High (DW-FORUM-30).</div>
          </Card>
        </div>
      )}

      {tab === 'creds' && (
        <div className="stack" style={{ gap: 14 }}>
          <Card title="Infostealer exposure" sub="Hudson Rock community data — counts of infected machines holding the organisation's logins; no credentials are fetched or stored">
            <Table rows={data.stealers} onRow={(r: any) => nav(`/orgs/${r.org_id}`)} empty="Exposure checks run weekly per organisation." cols={[
              { key: 'org_name', label: 'Organisation' },
              { key: 'emp', label: 'Employee devices', num: true, render: (r: any) => compact(r.extra?.employees), sort: (r: any) => r.extra?.employees },
              { key: 'last_emp', label: 'Last employee infection', render: (r: any) => day(r.extra?.last_employee), sort: (r: any) => r.extra?.last_employee || '' },
              { key: 'usr', label: 'Customer devices', num: true, render: (r: any) => compact(r.extra?.users), sort: (r: any) => r.extra?.users },
              { key: 'fam', label: 'Top stealer families', render: (r: any) => <span className="muted" style={{ fontSize: 12 }}>{Object.keys(r.extra?.families || {}).slice(0, 3).join(', ')}</span> },
              { key: 'url', label: '', render: (r: any) => <SourceLink url={r.url} label="Hudson Rock" /> }]} />
          </Card>
          <Card title="Latest public breaches" sub="Have I Been Pwned catalogue (CC BY 4.0)">
            <Table rows={data.breaches} cols={[
              { key: 'published', label: 'Added', render: (b: any) => day(b.published) }, { key: 'victim', label: 'Breach', render: (b: any) => <><b>{b.victim}</b><div className="muted mono" style={{ fontSize: 11 }}>{b.domain}</div></> },
              { key: 'org', label: 'Monitored', render: orgLink }, { key: 'pwn', label: 'Accounts', num: true, render: (b: any) => compact(b.extra?.pwn_count), sort: (b: any) => b.extra?.pwn_count },
              { key: 'dc', label: 'Data exposed', render: (b: any) => <span className="muted" style={{ fontSize: 12 }}>{(b.extra?.data_classes || []).slice(0, 4).join(', ')}</span> },
              { key: 'url', label: '', render: (b: any) => <SourceLink url={b.url} label="HIBP" /> }]} />
          </Card>
        </div>
      )}

      {tab === 'hacktivist' && (
        <div className="grid g-main-side">
          <Card title="Hacktivist DDoS target lists" sub="NoName057(16) DDoSia configurations decoded by CIRCL — the plotted targets, before or during attack">
            <Table rows={data.ddos} max={300} empty="No target lists in this window." cols={[
              { key: 'published', label: 'Listed', render: (l: any) => <When ts={l.published} /> }, { key: 'domain', label: 'Targeted domain', render: (l: any) => <span className="mono">{l.domain}</span> },
              { key: 'org', label: 'Monitored', render: orgLink, sort: (l: any) => (l.org_id ? 0 : 1) }, { key: 'hosts', label: 'Hosts', render: (l: any) => <span className="muted mono" style={{ fontSize: 11 }}>{(l.extra?.hosts || []).join(', ')}</span> },
              { key: 'url', label: '', render: (l: any) => <SourceLink url={l.url} label="witha.name" /> }]} />
          </Card>
          <Card title="Targets by country TLD">
            <HBar data={Object.entries((data.ddos as any[]).reduce((a: any, l: any) => { const t = (l.domain || '').split('.').pop(); a[t] = (a[t] || 0) + 1; return a }, {})).map(([t, n]) => ({ t: '.' + t, n })).sort((a: any, b: any) => b.n - a.n).slice(0, 12)} label="t" value="n" />
          </Card>
        </div>
      )}

      {tab === 'chatter' && (
        <div className="grid g-main-side">
          <Card title="Community chatter" sub="Hacker News, Mastodon, Reddit security communities — aggregated to topic; author identities are not stored">
            <div className="feed">
              {data.chatter.map((i: any) => (
                <div key={i.id} className="feed-item"><span className="pill">{i.publisher}</span>
                  <div><div className="t clamp3">{i.title}</div><div className="m"><When ts={i.published} />{(i.themes || []).slice(0, 3).map((t: string) => <span key={t} className="pill">{t}</span>)}</div></div>
                  <SourceLink url={i.url} /></div>))}
            </div>
          </Card>
          <Card title="What the chatter is about"><HBar data={data.chatter_themes} label="theme" value="n" onClick={d => nav(`/analyst?topic=${encodeURIComponent(d.theme)}`)} /></Card>
        </div>
      )}

      {tab === 'catalogue' && (
        <div className="grid g2">
          <Card title="Criminal forums, markets and channels (catalogue)" sub="names and status only from the deepdarkCTI community catalogue — no links are rendered" right={<SourceLink url="https://github.com/fastfire/deepdarkCTI" label="deepdarkCTI" />}>
            <Table rows={Object.entries(data.catalogue).map(([cat, s]: any) => ({ cat, online: s.ONLINE || 0, offline: (s.OFFLINE || 0) + (s.EXPIRED || 0), other: Object.entries(s).filter(([k]) => !['ONLINE', 'OFFLINE', 'EXPIRED'].includes(k)).reduce((a, [, v]: any) => a + v, 0) }))}
              cols={[{ key: 'cat', label: 'Category' }, { key: 'online', label: 'Online', num: true }, { key: 'offline', label: 'Offline / expired', num: true }, { key: 'other', label: 'Unknown', num: true }]} />
          </Card>
          <Card title="Leak-site tracker coverage" sub="RansomLook (CC BY 4.0)" right={<SourceLink url="https://www.ransomlook.io" label="RansomLook" />}>
            {data.ransomlook ? <div className="grid g2">{Object.entries(data.ransomlook).filter(([, v]) => typeof v === 'number').slice(0, 8).map(([k, v]: any) => <Stat key={k} label={k.replace(/_/g, ' ')} value={compact(v)} />)}</div> : <Empty>Collecting…</Empty>}
          </Card>
        </div>
      )}
      <PageSources cats={['Dark web', 'Chatter']} note="Metadata only, via third-party trackers — AEGIS never visits .onion sites, joins Telegram channels or stores credentials." />
    </div>
  )
}
