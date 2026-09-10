import { createContext, lazy, Suspense, useContext, useEffect, useRef, useState } from 'react'
import { NavLink, Route, Routes, useNavigate, useLocation } from 'react-router-dom'
import { Radar, Flame, Building2, ShieldAlert, Skull, Crosshair, Brain, Database, Search, Cpu, Activity, Moon, CloudMoon, Sun } from 'lucide-react'
import { useApi } from './lib/api'
import { ago } from './lib/format'
import { Seg } from './components/ui'
import { ThemeName, THEME } from './lib/chartTheme'
import { applyTheme } from './lib/theme'

function ThemeSwitch({ value, onChange }: { value: ThemeName; onChange: (t: ThemeName) => void }) {
  const opts: [ThemeName, any, string][] = [['dark', Moon, 'Dark'], ['dim', CloudMoon, 'Dim'], ['light', Sun, 'Light']]
  return (
    <div className="seg theme-seg" role="radiogroup" aria-label="Colour theme">
      {opts.map(([id, I, label]) => (
        <button key={id} role="radio" aria-checked={value === id} title={`${label} theme`} className={value === id ? 'on' : ''} onClick={() => onChange(id)}>
          <I size={13} /><span className="lbl">{label}</span>
        </button>
      ))}
    </div>
  )
}

const Overview = lazy(() => import('./pages/Overview'))
const Incidents = lazy(() => import('./pages/Incidents'))
const Orgs = lazy(() => import('./pages/Orgs'))
const OrgDetail = lazy(() => import('./pages/OrgDetail'))
const Exposure = lazy(() => import('./pages/Exposure'))
const DarkWeb = lazy(() => import('./pages/DarkWeb'))
const Adversaries = lazy(() => import('./pages/Adversaries'))
const Analyst = lazy(() => import('./pages/Analyst'))
const AIRisk = lazy(() => import('./pages/AIRisk'))
const Sources = lazy(() => import('./pages/Sources'))

export type Range = '7' | '30' | '90'
const RangeCtx = createContext<{ range: Range; setRange: (r: Range) => void }>({ range: '30', setRange: () => {} })
export const useRange = () => useContext(RangeCtx)

function GlobalSearch() {
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const [sel, setSel] = useState(0)
  const nav = useNavigate()
  const ref = useRef<HTMLInputElement>(null)
  const { data } = useApi<any[]>(q.trim().length >= 2 ? `/search?q=${encodeURIComponent(q.trim())}` : null, 600)
  const results = data || []
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === '/' && document.activeElement?.tagName !== 'INPUT') { e.preventDefault(); ref.current?.focus() } }
    window.addEventListener('keydown', h); return () => window.removeEventListener('keydown', h)
  }, [])
  const go = (r: any) => { setOpen(false); setQ(''); nav(r.href) }
  return (
    <div className="search">
      <Search size={15} />
      <input ref={ref} value={q} placeholder="Search organisations, incidents, CVEs, actors, vendors…  ( / )" onFocus={() => setOpen(true)} onBlur={() => setTimeout(() => setOpen(false), 150)}
        onChange={e => { setQ(e.target.value); setSel(0); setOpen(true) }}
        onKeyDown={e => { if (e.key === 'ArrowDown') setSel(s => Math.min(s + 1, results.length - 1)); if (e.key === 'ArrowUp') setSel(s => Math.max(0, s - 1)); if (e.key === 'Enter' && results[sel]) go(results[sel]) }} />
      {open && results.length > 0 && (
        <div className="search-results">
          {results.map((r, i) => (
            <a key={r.kind + r.href} className={i === sel ? 'sel' : ''} onMouseDown={() => go(r)}>
              <span className="kind">{r.kind}</span><span className="trunc">{r.label}</span><span className="muted trunc" style={{ marginLeft: 'auto', fontSize: 12 }}>{r.sub}</span>
            </a>
          ))}
        </div>
      )}
    </div>
  )
}

function LiveStatus() {
  const { data } = useApi<any>('/status', 20)
  if (!data) return <div className="live"><span className="pulse warn" />Connecting…</div>
  const healthy = data.sources_ok / Math.max(1, data.sources_total)
  return (
    <div className="live" title={`${data.sources_ok} of ${data.sources_total} sources returned data on their last run`}>
      <span className={`pulse ${healthy < 0.7 ? 'warn' : ''}`} />
      <span>{data.running ? `Collecting · ${data.running}` : 'Autonomous collection on'}</span>
      <span className="muted">· {data.sources_ok}/{data.sources_total} sources · updated {ago(data.last_update)}</span>
    </div>
  )
}

export default function App() {
  const [range, setRange] = useState<Range>('30')
  const [theme, setThemeState] = useState<ThemeName>(THEME)
  const changeTheme = (t: ThemeName) => { applyTheme(t); setThemeState(t) }
  const { data: counts } = useApi<any>('/nav-counts', 60)
  const loc = useLocation()
  useEffect(() => { document.querySelector('.page')?.scrollTo(0, 0) }, [loc.pathname])
  const N = (to: string, icon: any, label: string, count?: number, hot?: boolean) => {
    const I = icon
    return <NavLink to={to} end={to === '/'} className={({ isActive }) => (isActive ? 'active' : '')}><I size={16} />{label}{count !== undefined && <span className={`count ${hot ? 'hot' : ''}`}>{count}</span>}</NavLink>
  }
  return (
    <RangeCtx.Provider value={{ range, setRange }}>
      <div className="shell">
        <aside className="rail">
          <div className="brand">
            <div className="brand-mark"><Radar size={20} style={{ color: 'var(--accent)' }} /></div>
            <div><h1>AEGIS</h1><small>Cyber Risk Operations Center</small></div>
          </div>
          <nav className="nav">
            <div className="nav-sec">Watch floor</div>
            {N('/', Activity, 'Situation')}
            {N('/incidents', Flame, 'Incidents & impact', counts?.incidents_critical, (counts?.incidents_critical || 0) > 0)}
            {N('/orgs', Building2, 'Organisations', counts?.orgs_watch)}
            <div className="nav-sec">Threat picture</div>
            {N('/exposure', ShieldAlert, 'Exposure & vulns', counts?.kev_7d)}
            {N('/darkweb', Skull, 'Dark web & chatter', counts?.leaks_7d)}
            {N('/adversaries', Crosshair, 'Adversaries')}
            <div className="nav-sec">Intelligence</div>
            {N('/analyst', Brain, 'Analyst view')}
            {N('/ai', Cpu, 'AI risk')}
            {N('/sources', Database, 'Sources & method')}
          </nav>
          <div className="rail-foot">
            Passive, open sources only. No scanning, no purchased data, credentials never stored.
          </div>
        </aside>
        <div className="main">
          <header className="topbar">
            <GlobalSearch />
            <Seg options={[{ id: '7', label: '7d' }, { id: '30', label: '30d' }, { id: '90', label: '90d' }]} value={range} onChange={setRange} />
            <LiveStatus />
            <ThemeSwitch value={theme} onChange={changeTheme} />
          </header>
          <main className="page">
            <Suspense fallback={<div className="muted">Loading…</div>}>
              {/* keyed on theme: charts remount and read the new colour tokens */}
              <Routes key={theme}>
                <Route path="/" element={<Overview />} />
                <Route path="/incidents" element={<Incidents />} />
                <Route path="/incidents/:id" element={<Incidents />} />
                <Route path="/orgs" element={<Orgs />} />
                <Route path="/orgs/:id" element={<OrgDetail />} />
                <Route path="/exposure" element={<Exposure />} />
                <Route path="/darkweb" element={<DarkWeb />} />
                <Route path="/adversaries" element={<Adversaries />} />
                <Route path="/adversaries/:id" element={<Adversaries />} />
                <Route path="/analyst" element={<Analyst />} />
                <Route path="/ai" element={<AIRisk />} />
                <Route path="/sources" element={<Sources />} />
              </Routes>
            </Suspense>
          </main>
        </div>
      </div>
    </RangeCtx.Provider>
  )
}
