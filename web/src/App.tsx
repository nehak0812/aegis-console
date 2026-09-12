import { createContext, lazy, Suspense, useContext, useEffect, useRef, useState } from 'react'
import { NavLink, Route, Routes, useNavigate, useLocation } from 'react-router-dom'
import { Radar, Flame, Building2, ShieldAlert, Skull, Crosshair, Brain, Database, Search, Cpu, Activity, Moon, CloudMoon, Sun, Fingerprint, Timer, ShieldCheck, Workflow, Menu } from 'lucide-react'
import { ChainNav } from './components/chain'
import { GlossaryLayer } from './components/glossary'
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
const Impersonation = lazy(() => import('./pages/Impersonation'))
const Speed = lazy(() => import('./pages/Speed'))
const Prevent = lazy(() => import('./pages/Prevent'))
const Suppliers = lazy(() => import('./pages/Suppliers'))

function NotFound() {
  return (
    <div className="card" style={{ maxWidth: 560 }}>
      <h3 style={{ marginTop: 0 }}>Page not found</h3>
      <p className="muted">This view does not exist in this version of the console.</p>
      <div className="row" style={{ gap: 12 }}><NavLink to="/">Situation</NavLink><NavLink to="/orgs">Organisations</NavLink><NavLink to="/sources">Sources & method</NavLink></div>
    </div>
  )
}

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
  const { data: st } = useApi<any>('/status', 20)
  const loc = useLocation()
  const [menu, setMenu] = useState(false)  // phone / narrow screens: the navigation slides in
  useEffect(() => { document.querySelector('.page')?.scrollTo(0, 0); setMenu(false) }, [loc.pathname])
  // nav badges use fixed windows (not the range selector) — the tooltip says which
  const N = (to: string, icon: any, label: string, count?: number, hot?: boolean, hint?: string) => {
    const I = icon
    return <NavLink to={to} end={to === '/'} className={({ isActive }) => (isActive ? 'active' : '')}><I size={16} />{label}{count !== undefined && <span className={`count ${hot ? 'hot' : ''}`} title={hint}>{count}</span>}</NavLink>
  }
  return (
    <RangeCtx.Provider value={{ range, setRange }}>
      <div className="shell">
        <div className={`scrim ${menu ? 'open' : ''}`} onClick={() => setMenu(false)} aria-hidden />
        <aside className={`rail ${menu ? 'open' : ''}`}>
          <div className="brand">
            <div className="brand-mark"><Radar size={20} style={{ color: 'var(--accent)' }} /></div>
            <div><h1>AEGIS</h1><small>Cyber Risk Operations Center</small></div>
          </div>
          {/* ordered as the risk chain: the threat → the exposure → the response (see components/chain.tsx) */}
          <nav className="nav">
            {N('/', Activity, 'Situation')}
            <div className="nav-sec">The threat</div>
            {N('/incidents', Flame, 'Incidents & impact', counts?.incidents_critical, (counts?.incidents_critical || 0) > 0, 'Critical incidents · last 7 days')}
            {N('/speed', Timer, 'Speed & spread')}
            {N('/adversaries', Crosshair, 'Adversaries')}
            {N('/darkweb', Skull, 'Dark web & chatter', counts?.leaks_7d, false, 'leak-site listings · last 7 days')}
            {N('/analyst', Brain, 'Analyst view')}
            <div className="nav-sec">The exposure</div>
            {N('/exposure', ShieldAlert, 'Exposure & vulns', counts?.kev_7d, false, 'CVEs newly exploited (CISA KEV) · last 7 days')}
            {N('/impersonation', Fingerprint, 'Impersonation & IOCs', counts?.impersonation, (counts?.impersonation || 0) > 0, 'Critical / High impersonation findings · now')}
            {N('/suppliers', Workflow, 'Supply chain')}
            {N('/ai', Cpu, 'AI risk')}
            <div className="nav-sec">The response</div>
            {N('/orgs', Building2, 'Organisations', counts?.orgs_watch, false, 'monitored organisations · now')}
            {N('/prevent', ShieldCheck, 'Prevent & actions')}
            <div className="nav-sec">Method</div>
            {N('/sources', Database, 'Sources & method')}
          </nav>
          <div className="rail-foot">
            Passive, open sources only. No scanning, no purchased data, credentials never stored.
            {st?.version && <div className="mono" style={{ marginTop: 6 }}>AEGIS {st.version}</div>}
          </div>
        </aside>
        <div className="main">
          <header className="topbar">
            <button className="menu-btn" aria-label="Open navigation" onClick={() => setMenu(m => !m)}><Menu size={18} /></button>
            <GlobalSearch />
            <span title="Time window for incidents, reporting, dark-web activity, exploitation and speed. Each tile says which window it uses: “· 7d / 30d / 90d” follows this selector, “· now” is the current state (levels, findings, act-by deadlines), and a few context charts use a fixed period stated in their subtitle. AEGIS has only collected since it was deployed, so longer windows can match shorter ones.">
              <Seg options={[{ id: '7', label: '7d' }, { id: '30', label: '30d' }, { id: '90', label: '90d' }]} value={range} onChange={setRange} />
            </span>
            <span className="hide-sm"><LiveStatus /></span>
            <ThemeSwitch value={theme} onChange={changeTheme} />
          </header>
          <main className="page">
            <ChainNav where="top" />
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
                <Route path="/impersonation" element={<Impersonation />} />
                <Route path="/speed" element={<Speed />} />
                <Route path="/prevent" element={<Prevent />} />
                <Route path="/suppliers" element={<Suppliers />} />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </Suspense>
            <ChainNav where="bottom" />
          </main>
          <GlossaryLayer />
        </div>
      </div>
    </RangeCtx.Provider>
  )
}
