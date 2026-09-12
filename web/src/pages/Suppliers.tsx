import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ResponsiveSankey } from '@nivo/sankey'
import { useApi } from '../lib/api'
import { Card, Empty, Sev, SourceLink, StoryStrip, SectionLabel, PageSources, Table } from '../components/ui'
import { SERIES, SURFACE, INK2, nivoTheme } from '../lib/chartTheme'
import { countryName, day } from '../lib/format'

/** Supply chain (Exiger-inspired, passive and free sources only): who the providers rely on, where that concentrates,
 *  who owns them, whether they signed CISA's Secure by Design pledge, and exact-name screening matches to review. */
export default function Suppliers() {
  const nav = useNavigate()
  const { data } = useApi<any>('/suppliers', 600)
  const [n, setN] = useState(12)
  if (!data) return <div className="muted">Mapping the supply chain…</div>
  if (!data.collected) return <Empty>The supplier-intelligence collector has not run yet (daily). It maps each provider's own mail, DNS and SPF providers, ownership (GLEIF), Secure by Design pledge status and entity screening.</Empty>
  const t = data.totals
  const top = data.concentration[0]
  const maxT = Math.max(1, ...data.concentration.slice(0, n).map((c: any) => c.total))
  const review = data.providers.filter((p: any) => p.screening?.length)

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="eyebrow">Supply chain · now</div>
          <h2>Who your providers rely on — and where that quietly concentrates</h2>
          <p>AEGIS already sees each organisation's providers in public DNS. Here the same passive method is applied to the providers themselves, revealing
            who hosts their DNS (if it fails, the provider can become unreachable) and their mail (the route for supplier-email compromise and invoice fraud) —
            the fourth parties. Organisations that never use a fourth party directly may still depend on it through a provider. Ownership comes from GLEIF,
            pledge status from CISA's Secure by Design list, and screening from the US Consolidated Screening List and the UK Sanctions List — entities only,
            exact names only, always for human review.</p>
        </div>
      </div>

      <StoryStrip items={[
        { label: 'Providers mapped', value: t.providers, title: 'providers with their own DNS and mail mapped', sub: `${t.infra_links} provider → fourth-party links (NS and MX records)` },
        { label: 'Hidden concentration', value: top ? top.total : '—', title: top ? `organisations depend on ${top.name}` : '—',
          sub: top ? `${top.indirect} of them only through one of their providers (e.g. ${top.carried_by.slice(0, 2).map((c: any) => c.provider).join(', ')})` : '' },
        { label: 'Ownership', value: t.with_lei, title: 'providers matched to a legal entity (GLEIF)', sub: `${t.with_parent} have an ultimate parent on record — e.g. a provider owned by another provider` },
        { label: 'Secure by Design', value: t.sbd_signers, title: 'providers signed CISA\'s pledge', sub: 'a public commitment on MFA, default passwords, patching and disclosure' },
        { label: 'Screening to review', value: t.screening_to_review, title: 'exact name matches on entity lists', sub: 'a name match is not a determination — review before any action' },
      ]} />

      <div className="grid g-main-side" style={{ marginBottom: 14 }}>
        <Card title="Hidden concentration" sub="monitored organisations that depend on each fourth party, directly or only because one of their providers' DNS or mail runs on it">
          <div className="row wrap" style={{ gap: 14, fontSize: 12, marginBottom: 8 }}>
            <span className="row" style={{ gap: 5 }}><span style={{ width: 10, height: 10, borderRadius: 2, background: SERIES[0] }} />directly (their own DNS)</span>
            <span className="row" style={{ gap: 5 }}><span style={{ width: 10, height: 10, borderRadius: 2, background: SERIES[4] || SERIES[1] }} />only through one of their providers</span>
          </div>
          <div className="stack" style={{ gap: 7 }}>
            {data.concentration.slice(0, n).map((c: any) => (
              <div key={c.name} title={`carried by ${c.carried_by.map((x: any) => x.provider).join(', ')}`}
                style={{ display: 'grid', gridTemplateColumns: 'minmax(80px, 160px) minmax(0,1fr) auto', gap: 10, alignItems: 'center', fontSize: 12.5 }}>
                <b className="trunc">{c.name}</b>
                <div style={{ display: 'flex', height: 12, background: 'var(--hair)', borderRadius: 6, overflow: 'hidden' }}>
                  <div style={{ width: `${(c.direct / maxT) * 100}%`, background: SERIES[0] }} />
                  <div style={{ width: `${(c.indirect / maxT) * 100}%`, background: SERIES[4] || SERIES[1], borderLeft: c.direct ? `2px solid ${SURFACE}` : undefined }} />
                </div>
                <span className="muted" style={{ textAlign: 'right' }}><b style={{ color: 'var(--ink)' }}>{c.total}</b> · {c.indirect} indirect</span>
              </div>))}
            {data.concentration.length > n && <a className="srclink" onClick={() => setN(v => v + 12)}>Show more</a>}
          </div>
        </Card>
        <Card title="What this means" sub="reading the chart">
          <div className="stack" style={{ gap: 8, fontSize: 13 }}>
            <div>A DNS outage at a fourth party can make every provider whose name servers it hosts unreachable; a compromise of a provider's mail host opens the door to convincing supplier-email fraud. Both reach organisations that never chose that fourth party — the "only through a provider" share, invisible in their own DNS.</div>
            <div className="muted" style={{ fontSize: 12 }}>Evidence is the providers' public NS and MX records only. SPF includes (email-sending services) and domain-verification TXT tokens are excluded: they show an account, not operational dependence. Cloud hosting behind a provider's web front end is not visible passively.</div>
            {top && <a className="srclink" onClick={() => nav(`/orgs?provider=${encodeURIComponent(top.name)}`)}>Organisations using {top.name} directly →</a>}
          </div>
        </Card>
      </div>

      <Card title="How dependence flows" sub="the ten most-used providers (left, sized by monitored organisations) and the infrastructure providers they rely on (right)">
        {data.sankey.links.length ? (
          <div style={{ height: 520 }}>
            <ResponsiveSankey data={data.sankey as any} margin={{ top: 10, right: 170, bottom: 10, left: 170 }} align="justify" nodeOpacity={1} nodeThickness={14}
              nodeSpacing={10} nodeBorderWidth={0} linkOpacity={0.45} linkHoverOpacity={0.8} linkBlendMode="normal" enableLinkGradient colors={SERIES as any}
              label={(nd: any) => String(nd.id).slice(2)} labelPosition="outside" labelPadding={8} labelTextColor={INK2 as any} theme={nivoTheme as any}
              nodeTooltip={({ node }: any) => <div className="tip"><strong>{String(node.id).slice(2)}</strong><div>{String(node.id).startsWith('P:') ? 'provider' : 'fourth party'} · weight {node.value}</div></div>}
              linkTooltip={({ link }: any) => <div className="tip">{String(link.source.id).slice(2)} → {String(link.target.id).slice(2)}<div>{link.value} monitored organisations use {String(link.source.id).slice(2)}</div></div>} />
          </div>) : <Empty>No provider infrastructure mapped yet.</Empty>}
      </Card>

      <SectionLabel>Every provider · ownership, pledge, screening and what it relies on</SectionLabel>
      <Card className="flush">
        <div style={{ padding: '4px 8px 10px' }}>
          <Table rows={data.providers} max={200} onRow={(p: any) => nav(`/orgs?provider=${encodeURIComponent(p.name)}`)} initialSort={['dependents', 'desc']} cols={[
            { key: 'name', label: 'Provider', render: (p: any) => <><b>{p.name}</b><div className="muted" style={{ fontSize: 11.5 }}>{p.category} · {p.domain}</div></> },
            { key: 'dependents', label: 'Monitored users', num: true },
            { key: 'fourth', label: 'DNS and mail run on', render: (p: any) => (
              <span className="row wrap" style={{ gap: 4 }}>{p.fourth.slice(0, 5).map((f: any) => <span key={f.name + f.kind} className="pill" title={f.evidence}>{f.name} <span className="muted">{(f.kind || '').toUpperCase()}</span></span>)}
                {p.fourth.length > 5 && <span className="muted" style={{ fontSize: 11.5 }}>+{p.fourth.length - 5}</span>}{!p.fourth.length && <span className="muted">—</span>}</span>), sort: (p: any) => p.fourth.length },
            { key: 'legal_name', label: 'Legal entity · parent', render: (p: any) => p.legal_name ? (
              <div style={{ fontSize: 12.5 }}>{p.legal_name}{p.country && <span className="muted"> · {countryName(p.country)}</span>}
                {p.parent && <div className="muted" style={{ fontSize: 11.5 }}>owned by {p.parent.name}{p.parent.country ? ` (${countryName(p.parent.country)})` : ''}</div>}</div>) : <span className="muted">no confident GLEIF match</span> },
            { key: 'sbd_pledge', label: 'Secure by Design', render: (p: any) => (p.sbd_pledge ? <span className="pill">signed</span> : p.sbd_pledge === false ? <span className="muted">not on the list</span> : <span className="muted">—</span>),
              sort: (p: any) => (p.sbd_pledge ? 0 : 1) },
            { key: 'screening', label: 'Screening', render: (p: any) => (p.screening?.length ? <span className="pill" title={p.screening.map((s: any) => `${s.matched} — ${s.source}`).join('; ')}>name match · review</span> : <span className="muted">no match</span>),
              sort: (p: any) => (p.screening?.length ? 0 : 1) },
            { key: 'issue', label: 'Issue now', render: (p: any) => (p.issue ? <a className="clickable" onClick={e => { e.stopPropagation(); if (p.issue.id) nav(`/incidents/${p.issue.id}`) }}><Sev level={p.issue.severity} compact /> <span style={{ fontSize: 12 }}>{p.issue.title}</span></a> : ''),
              sort: (p: any) => (p.issue ? 0 : 1) },
          ]} />
        </div>
      </Card>

      {review.length > 0 && (
        <Card title="Screening matches to review" sub="exact normalised-name matches on government entity lists — not a determination">
          <div className="stack" style={{ gap: 8 }}>{review.flatMap((p: any) => p.screening.map((s: any, i: number) => (
            <div key={p.name + i} style={{ fontSize: 13 }}><b>{p.name}</b> matched <b>{s.matched}</b> on the {s.list} ({s.source}{s.programme ? ` · ${s.programme}` : ''}).
              <span className="muted"> Compare the listed entity's address and identifiers with the provider before drawing any conclusion.</span> {s.url && <SourceLink url={s.url} label="list" />}</div>)))}
            <div className="muted" style={{ fontSize: 12 }}>{data.meta?.screening_note}</div>
          </div>
        </Card>)}

      <PageSources cats={['Registry', 'Threat intel', 'Attack surface']}
        note={<>Supplier intelligence last collected {data.meta?.run_at ? day(data.meta.run_at) : '—'}: DNS over HTTPS (Google, Cloudflare), GLEIF Level 2, the US Consolidated Screening List (trade.gov), the UK Sanctions List (FCDO) and CISA's Secure by Design pledge signers. Individuals are never stored.</>} />
    </div>
  )
}
