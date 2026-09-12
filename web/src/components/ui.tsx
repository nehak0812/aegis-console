import { ReactNode, useMemo, useState, useRef, useEffect } from 'react'
import { AlertOctagon, AlertTriangle, AlertCircle, Info, ExternalLink, ChevronDown, ChevronUp, Timer, X, Check } from 'lucide-react'
import { useApi, Level } from '../lib/api'
import { SEV_COLOR, SEV_LABEL, SEV_ORDER } from '../lib/chartTheme'
import { ago, host } from '../lib/format'
import { useNavigate } from 'react-router-dom'

const SEV_ICON = { critical: AlertOctagon, high: AlertTriangle, medium: AlertCircle, low: Info }

export function useRules() {
  const { data } = useApi<{ id: string; level: Level; rule: string; applies_to: string }[]>('/rules', 3600)
  return useMemo(() => Object.fromEntries((data || []).map(r => [r.id, r])), [data])
}

/** Severity: always icon + label (never colour alone). Hover shows the rule that assigned it. */
export function Sev({ level, rule, compact }: { level?: string | null; rule?: string | null; compact?: boolean }) {
  const rules = useRules()
  if (!level) return null
  const Icon = SEV_ICON[level as Level] || Info
  const why = rule && rules[rule] ? `${rule}: ${rules[rule].rule}` : undefined
  return (
    <span className={`sev ${level}`} title={why}>
      <Icon size={12} strokeWidth={2.4} />
      {!compact && SEV_LABEL[level]}
    </span>
  )
}

export function Why({ rule, level }: { rule?: string | null; level?: string | null }) {
  const rules = useRules()
  if (!rule) return null
  const r = rules[rule]
  return (
    <div className="why"><b>Why {SEV_LABEL[level || r?.level || 'low']}:</b> {r?.rule || rule} <span className="muted mono">[{rule}]</span></div>
  )
}

/** "Act by" clock: time left (or overdue) against the deadline rule; hover shows the rule. Always icon + words, never colour alone. */
export function ActBy({ ts, rule }: { ts?: string | null; rule?: string | null }) {
  const rules = useRules()
  if (!ts) return null
  const ms = Date.parse(ts) - Date.now()
  const h = Math.round(Math.abs(ms) / 3600000)
  const span = h < 48 ? `${h}h` : `${Math.round(h / 24)}d`
  const txt = ms < 0 ? `overdue by ${span}` : `act within ${span}`
  const why = rule && rules[rule] ? `${rule}: ${rules[rule].rule}` : undefined
  return (
    <span className="pill" title={why} style={ms < 0 ? { borderColor: 'var(--critical)', color: 'var(--ink)' } : rule === 'DL-72H' ? { borderColor: 'var(--high)' } : undefined}>
      <Timer size={11} />{txt} · by {new Date(ts).toLocaleDateString(undefined, { day: 'numeric', month: 'short' })}
    </span>
  )
}

export function SourceLink({ url, label }: { url?: string | null; label?: string }) {
  if (!url) return null
  return (
    <a className="srclink" href={url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()} title={url}>
      {label || host(url) || 'Open source'} <ExternalLink size={11} />
    </a>
  )
}

export function Card({ title, sub, right, children, className = '', onClick }: { title?: ReactNode; sub?: ReactNode; right?: ReactNode; children?: ReactNode; className?: string; onClick?: () => void }) {
  return (
    <section className={`card ${onClick ? 'clickable' : ''} ${className}`} onClick={onClick}>
      {(title || right) && (
        <div className="card-h">
          {title && <h3>{title}</h3>}
          {sub && <span className="sub">{sub}</span>}
          {right && <div className="right">{right}</div>}
        </div>
      )}
      {children}
    </section>
  )
}

export function Stat({ label, value, hint, hero, onClick }: { label: string; value: ReactNode; hint?: ReactNode; hero?: boolean; onClick?: () => void }) {
  return (
    <div className={`card stat ${hero ? 'hero' : ''} ${onClick ? 'clickable' : ''}`} onClick={onClick}>
      <span className="label">{label}</span>
      <span className="value">{value}</span>
      {hint && <span className="hint">{hint}</span>}
    </div>
  )
}

/** Horizontal stacked severity bar with a 2px surface gap between segments. */
export function SevBar({ counts, height = 8 }: { counts: Record<string, number>; height?: number }) {
  const total = SEV_ORDER.reduce((a, k) => a + (counts[k] || 0), 0)
  if (!total) return <div className="sevbar" style={{ height }}><span style={{ flex: 1, background: 'var(--hair)' }} /></div>
  return (
    <div className="sevbar" style={{ height }} title={SEV_ORDER.map(k => `${SEV_LABEL[k]}: ${counts[k] || 0}`).join(' · ')}>
      {SEV_ORDER.filter(k => counts[k]).map(k => <span key={k} style={{ flex: counts[k], background: SEV_COLOR[k] }} />)}
    </div>
  )
}

export function SevCounts({ counts }: { counts: Record<string, number> }) {
  return (
    <span className="row" style={{ gap: 6 }}>
      {SEV_ORDER.filter(k => counts[k]).map(k => <span key={k} className={`sev ${k}`}>{counts[k]} {SEV_LABEL[k]}</span>)}
    </span>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: ReactNode; count?: number }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map(t => (
        <button key={t.id} role="tab" aria-selected={value === t.id} className={value === t.id ? 'on' : ''} onClick={() => onChange(t.id)}>
          {t.label}{t.count !== undefined && <span className="pill" style={{ padding: '0 6px' }}>{t.count}</span>}
        </button>
      ))}
    </div>
  )
}

export function Seg<T extends string>({ options, value, onChange }: { options: { id: T; label: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="seg">
      {options.map(o => <button key={o.id} className={value === o.id ? 'on' : ''} onClick={() => onChange(o.id)}>{o.label}</button>)}
    </div>
  )
}

export function When({ ts }: { ts?: string | null }) {
  return <span className="muted" title={ts || ''}>{ago(ts)}</span>
}

export type Col<T> = { key: string; label: string; render?: (r: T) => ReactNode; sort?: (r: T) => any; num?: boolean; width?: number | string }

export function Table<T>({ rows, cols, onRow, initialSort, max = 500, empty }: { rows: T[]; cols: Col<T>[]; onRow?: (r: T) => void; initialSort?: [string, 'asc' | 'desc']; max?: number; empty?: ReactNode }) {
  const [sort, setSort] = useState<[string, 'asc' | 'desc'] | undefined>(initialSort)
  const sorted = useMemo(() => {
    if (!sort) return rows
    const c = cols.find(c => c.key === sort[0])
    if (!c) return rows
    const f = c.sort || ((r: any) => r[c.key])
    return [...rows].sort((a, b) => {
      const x = f(a), y = f(b)
      const v = x === y ? 0 : x === undefined || x === null ? 1 : y === undefined || y === null ? -1 : x > y ? 1 : -1
      return sort[1] === 'asc' ? v : -v
    })
  }, [rows, sort, cols])
  if (!rows.length) return <Empty>{empty || 'No records.'}</Empty>
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <thead>
          <tr>
            {cols.map(c => (
              <th key={c.key} className={c.num ? 'num' : ''} style={{ width: c.width }} onClick={() => setSort(s => [c.key, s && s[0] === c.key && s[1] === 'desc' ? 'asc' : 'desc'])}>
                {c.label}{sort && sort[0] === c.key && (sort[1] === 'desc' ? <ChevronDown size={11} /> : <ChevronUp size={11} />)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.slice(0, max).map((r, i) => (
            <tr key={i} className={onRow ? 'click' : ''} onClick={() => onRow?.(r)}>
              {cols.map(c => <td key={c.key} className={c.num ? 'num' : ''}>{c.render ? c.render(r) : (r as any)[c.key]}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
      {sorted.length > max && <div className="muted" style={{ padding: 8, fontSize: 12 }}>Showing {max} of {sorted.length}.</div>}
    </div>
  )
}

const CONF_TIP: Record<string, string> = {
  confirmed: 'Confirmed: observed directly (DNS / RDAP / certificate record, CVE on an owned host, domain/CIK/LEI match, SEC filing).',
  likely: 'Likely: exact name or domain match in a third-party dataset, product seen without version, or DNS-evidenced provider.',
  unconfirmed: 'Unconfirmed: text mention, hostname-inferred product or forum claim — never rated above High.',
}
/** Confidence of the evidence behind a finding or action — always shown in words next to the level. */
export function Confidence({ c }: { c?: string | null }) {
  if (!c) return null
  return <span className="pill" title={CONF_TIP[c]} style={{ fontSize: 11 }}>{c}</span>
}

/* ---- the common page shape: summarise (StoryStrip) → visualise → details (SectionLabel) → sources (PageSources) ---- */

/** The page's story in 3–4 numbers, each with one sentence; click to jump to its detail. */
export function StoryStrip({ items }: { items: { label: string; value: ReactNode; title: ReactNode; sub?: ReactNode; onClick?: () => void }[] }) {
  return (
    <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, marginBottom: 14 }}>
      {items.map((c, i) => (
        <div key={i} className={`card ${c.onClick ? 'clickable' : ''}`} onClick={c.onClick} role={c.onClick ? 'button' : undefined} tabIndex={c.onClick ? 0 : undefined}
          onKeyDown={e => { if (c.onClick && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); c.onClick() } }}>
          <div className="muted" style={{ fontSize: 11.5, textTransform: 'uppercase', letterSpacing: '.06em' }}>{c.label}</div>
          <div style={{ fontSize: 30, fontWeight: 700, lineHeight: 1.15, margin: '6px 0 2px' }}>{c.value}</div>
          <div style={{ fontSize: 13, fontWeight: 600 }}>{c.title}</div>
          {c.sub && <div className="muted clamp2" style={{ fontSize: 12, marginTop: 4 }}>{c.sub}</div>}
        </div>))}
    </div>
  )
}

/** Divider between the summary, the details and the sources of a page. */
export function SectionLabel({ children }: { children: ReactNode }) {
  return <div className="eyebrow" style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '22px 0 10px' }}>{children}<span style={{ flex: 1, height: 1, background: 'var(--hair)' }} /></div>
}

const SRC_STATE: Record<string, string> = { OK: 'live', EMPTY: 'no new data', DEGRADED: 'degraded', DISABLED: 'disabled', RUNNING: 'collecting', PENDING: 'queued' }
/** Footer: which sources feed this page, with live status now. `cats` = source categories (all when omitted). */
export function PageSources({ cats, note }: { cats?: string[]; note?: ReactNode }) {
  const { data } = useApi<any>('/sources', 300)
  const nav = useNavigate()
  if (!data) return null
  const rows = (data.sources as any[]).filter(s => !cats || cats.includes(s.category))
  const live = rows.filter(s => s.status === 'OK').length
  const bad = rows.filter(s => s.status === 'DEGRADED').length
  return (
    <>
      <SectionLabel>Sources</SectionLabel>
      <Card title="Where this page's data comes from" sub={`${rows.length} passive, free and open sources · ${live} live${bad ? ` · ${bad} degraded` : ''} · status now · hover for details`}
        right={<a className="srclink" onClick={() => nav('/sources')}>All sources & method →</a>}>
        <div className="row wrap" style={{ gap: 6 }}>
          {rows.map(s => (
            <a key={s.id} className="pill btn" href={s.homepage} target="_blank" rel="noopener noreferrer"
              title={`${s.publisher || s.name} · ${SRC_STATE[s.status] || s.status}${s.last_ok ? ` · last success ${ago(s.last_ok)}` : ''}${s.notes ? ` — ${s.notes}` : ''}`}>
              <span aria-hidden style={{ width: 7, height: 7, borderRadius: 999, background: s.status === 'OK' ? 'var(--good)' : s.status === 'DEGRADED' ? 'var(--high)' : 'var(--muted)' }} />
              {s.name}{s.status !== 'OK' && <span className="muted"> · {SRC_STATE[s.status] || s.status}</span>}
            </a>))}
        </div>
        {note && <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>{note}</div>}
      </Card>
    </>
  )
}

export function Legend({ items }: { items: { label: string; color: string }[] }) {
  return <div className="legend">{items.map(i => <span key={i.label}><i style={{ background: i.color }} />{i.label}</span>)}</div>
}

export type Option = { id: string; label?: string; count?: number }

/** Checkbox dropdown for filters that accept several values at once. */
export function MultiSelect({ label, options, value, onChange, width = 190, searchAfter = 10 }:
  { label: string; options: Option[]; value: string[]; onChange: (v: string[]) => void; width?: number; searchAfter?: number }) {
  const [open, setOpen] = useState(false)
  const [find, setFind] = useState('')
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const away = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false) }
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', away); document.addEventListener('keydown', esc)
    return () => { document.removeEventListener('mousedown', away); document.removeEventListener('keydown', esc) }
  }, [open])
  useEffect(() => { if (!open) setFind('') }, [open])

  const shown = useMemo(() => {
    const f = find.trim().toLowerCase()
    return f ? options.filter(o => (o.label ?? o.id).toLowerCase().includes(f)) : options
  }, [options, find])
  const toggle = (id: string) => onChange(value.includes(id) ? value.filter(v => v !== id) : [...value, id])
  const text = !value.length ? label
    : value.length === 1 ? (options.find(o => o.id === value[0])?.label ?? value[0])
      : `${value.length} selected`

  return (
    <div className="multi" ref={ref} style={{ width }}>
      <button className={`multi-btn${value.length ? ' on' : ''}`} onClick={() => setOpen(o => !o)} title={value.length ? value.map(v => options.find(o => o.id === v)?.label ?? v).join(', ') : label}>
        <span className="multi-text">{text}</span>
        {value.length > 0 && <X size={13} className="multi-x" role="button" aria-label={`Clear ${label}`}
          onClick={e => { e.stopPropagation(); onChange([]); setOpen(false) }} />}
        <ChevronDown size={13} className="multi-caret" />
      </button>
      {open && (
        <div className="multi-menu">
          {options.length > searchAfter && (
            <input className="multi-find" autoFocus value={find} placeholder="Filter…" onChange={e => setFind(e.target.value)} />
          )}
          <div className="multi-list">
            {!shown.length && <div className="muted" style={{ padding: '6px 8px', fontSize: 12 }}>No match.</div>}
            {shown.map(o => {
              const on = value.includes(o.id)
              return (
                <button key={o.id} className={`multi-opt${on ? ' on' : ''}`} onClick={() => toggle(o.id)}>
                  <i className="multi-box">{on && <Check size={11} />}</i>
                  <span className="multi-opt-label">{o.label ?? o.id}</span>
                  {o.count != null && <b>{o.count}</b>}
                </button>
              )
            })}
          </div>
          {value.length > 0 && <button className="multi-clear" onClick={() => onChange([])}>Clear {value.length} selected</button>}
        </div>
      )}
    </div>
  )
}
