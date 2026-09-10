import { ReactNode, useMemo, useState } from 'react'
import { AlertOctagon, AlertTriangle, AlertCircle, Info, ExternalLink, ChevronDown, ChevronUp } from 'lucide-react'
import { useApi, Level } from '../lib/api'
import { SEV_COLOR, SEV_LABEL, SEV_ORDER } from '../lib/chartTheme'
import { ago, host } from '../lib/format'

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

export function Legend({ items }: { items: { label: string; color: string }[] }) {
  return <div className="legend">{items.map(i => <span key={i.label}><i style={{ background: i.color }} />{i.label}</span>)}</div>
}
