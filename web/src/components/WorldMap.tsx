import { useEffect, useMemo, useRef, useState } from 'react'
import { geoNaturalEarth1, geoPath, geoGraticule10, geoCentroid } from 'd3-geo'
import { feature } from 'topojson-client'
import world from 'world-atlas/countries-110m.json'
import { Plus, Minus, RotateCcw } from 'lucide-react'
import { SEV_COLOR, BLUE_RAMP, SERIES, SURFACE } from '../lib/chartTheme'

// ISO alpha-2 → world-atlas (Natural Earth) country name
const A2N: Record<string, string> = {
  US: 'United States of America', GB: 'United Kingdom', DE: 'Germany', FR: 'France', NL: 'Netherlands', CH: 'Switzerland', ES: 'Spain',
  IT: 'Italy', IE: 'Ireland', SE: 'Sweden', NO: 'Norway', DK: 'Denmark', FI: 'Finland', BE: 'Belgium', AT: 'Austria', CA: 'Canada',
  AU: 'Australia', JP: 'Japan', IN: 'India', BR: 'Brazil', MX: 'Mexico', PT: 'Portugal', PL: 'Poland', CN: 'China', KR: 'South Korea',
  IL: 'Israel', AE: 'United Arab Emirates', SA: 'Saudi Arabia', ZA: 'South Africa', TW: 'Taiwan', RU: 'Russia', IR: 'Iran',
  KP: 'North Korea', UA: 'Ukraine', TR: 'Turkey', AR: 'Argentina', CO: 'Colombia', CL: 'Chile', NZ: 'New Zealand', PE: 'Peru',
  ID: 'Indonesia', MY: 'Malaysia', TH: 'Thailand', VN: 'Vietnam', PH: 'Philippines', EG: 'Egypt', NG: 'Nigeria', KE: 'Kenya',
  MA: 'Morocco', GR: 'Greece', CZ: 'Czechia', RO: 'Romania', HU: 'Hungary', SK: 'Slovakia', BG: 'Bulgaria', HR: 'Croatia',
  RS: 'Serbia', LU: 'Luxembourg', PK: 'Pakistan', BD: 'Bangladesh', SG: 'Malaysia', HK: 'China', QA: 'Qatar', KW: 'Kuwait',
  EC: 'Ecuador', VE: 'Venezuela', DO: 'Dominican Rep.', PR: 'Puerto Rico', IS: 'Iceland', EE: 'Estonia', LV: 'Latvia', LT: 'Lithuania',
  SI: 'Slovenia', CY: 'Cyprus', JO: 'Jordan', LB: 'Lebanon', OM: 'Oman', BH: 'Qatar', TN: 'Tunisia', DZ: 'Algeria', GH: 'Ghana',
  UY: 'Uruguay', PY: 'Paraguay', BO: 'Bolivia', CR: 'Costa Rica', PA: 'Panama', GT: 'Guatemala', KZ: 'Kazakhstan', BY: 'Belarus',
}

export type MapPoint = { id: string; lat?: number | null; lon?: number | null; country?: string | null; level?: string | null; label: string; sub?: string; onClick?: () => void; pulse?: boolean }

const W = 960, H = 470
const K_MAX = 12
// Quick zoom targets: [west, south, east, north] in degrees
const REGIONS: { id: string; label: string; box?: [number, number, number, number] }[] = [
  { id: 'world', label: 'World' },
  { id: 'na', label: 'North America', box: [-128, 14, -60, 56] },
  { id: 'eu', label: 'Europe', box: [-12, 35, 32, 62] },
  { id: 'uk', label: 'UK & Benelux', box: [-9, 49, 10, 59] },
  { id: 'apac', label: 'Asia-Pacific', box: [68, -44, 178, 46] },
  { id: 'latam', label: 'Latin America', box: [-92, -56, -32, 24] },
]

type View = { k: number; x: number; y: number }
const ID: View = { k: 1, x: 0, y: 0 }
const clampV = (v: View): View => {
  const k = Math.min(K_MAX, Math.max(1, v.k))
  return { k, x: Math.min(0, Math.max(W - W * k, v.x)), y: Math.min(0, Math.max(H - H * k, v.y)) }
}

export default function WorldMap({ points = [], choropleth, height, onCountry, zoom = true }: { points?: MapPoint[]; choropleth?: Record<string, number>; height?: number; onCountry?: (a2: string) => void; zoom?: boolean }) {
  const [hover, setHover] = useState<{ x: number; y: number; p?: MapPoint; country?: string; n?: number } | null>(null)
  const [view, setView] = useState<View>(ID)
  const [region, setRegion] = useState('world')
  const [dragging, setDragging] = useState(false)
  const [hint, setHint] = useState(false)
  const wrap = useRef<HTMLDivElement>(null)
  const svg = useRef<SVGSVGElement>(null)
  const viewRef = useRef(view); viewRef.current = view
  const drag = useRef<{ px: number; py: number; v: View; moved: boolean } | null>(null)
  const suppressClick = useRef(false)
  const anim = useRef<number>(0)

  const { countries, path, proj, centroids, grat } = useMemo(() => {
    const fc: any = feature(world as any, (world as any).objects.countries)
    const proj = geoNaturalEarth1().fitExtent([[6, 6], [W - 6, H - 6]], { type: 'Sphere' } as any)
    const path = geoPath(proj)
    const centroids: Record<string, [number, number]> = {}
    for (const f of fc.features) centroids[f.properties.name] = geoCentroid(f) as [number, number]
    return { countries: fc.features, path, proj, centroids, grat: path(geoGraticule10()) }
  }, [])

  const n2a = useMemo(() => Object.fromEntries(Object.entries(A2N).map(([a, n]) => [n, a])), [])
  const max = useMemo(() => Math.max(1, ...Object.values(choropleth || {})), [choropleth])

  const placed = useMemo(() => points.map(p => {
    let ll: [number, number] | null = p.lat != null && p.lon != null ? [p.lon, p.lat] : null
    let approx = false
    if (!ll && p.country && A2N[p.country.toUpperCase()]) { ll = centroids[A2N[p.country.toUpperCase()]]; approx = true }
    if (!ll) return null
    const xy = proj(ll)
    if (!xy) return null
    // deterministic jitter for country-centroid points so stacked markers stay individually hoverable
    if (approx) { let h = 0; for (const c of p.id) h = (h * 31 + c.charCodeAt(0)) | 0; xy[0] += ((h & 255) / 255 - 0.5) * 18; xy[1] += (((h >> 8) & 255) / 255 - 0.5) * 12 }
    return { ...p, x: xy[0], y: xy[1], approx }
  }).filter(Boolean) as (MapPoint & { x: number; y: number; approx: boolean })[], [points, proj, centroids])

  // --- zoom & pan (all in the SVG's own 960×470 coordinate space) ---
  const toSvg = (cx: number, cy: number): [number, number] => {
    const el = svg.current
    const m = el?.getScreenCTM()
    if (!el || !m) return [W / 2, H / 2]
    const pt = el.createSVGPoint(); pt.x = cx; pt.y = cy
    const r = pt.matrixTransform(m.inverse())
    return [r.x, r.y]
  }
  const zoomAround = (v: View, sx: number, sy: number, f: number): View => {
    const k = Math.min(K_MAX, Math.max(1, v.k * f))
    return clampV({ k, x: sx - ((sx - v.x) * k) / v.k, y: sy - ((sy - v.y) * k) / v.k })
  }
  const animateTo = (to: View) => {
    cancelAnimationFrame(anim.current)
    const from = viewRef.current, t0 = performance.now(), dur = 380
    const step = (t: number) => {
      const u = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - u, 3)
      // interpolate scale geometrically so the motion feels even
      const k = from.k * Math.pow(to.k / from.k, e)
      setView({ k, x: from.x + (to.x - from.x) * e, y: from.y + (to.y - from.y) * e })
      if (u < 1) anim.current = requestAnimationFrame(step)
    }
    anim.current = requestAnimationFrame(step)
  }
  const goRegion = (id: string) => {
    setRegion(id)
    const r = REGIONS.find(x => x.id === id)
    if (!r?.box) { animateTo(ID); return }
    const [w, s, e, n] = r.box
    const xs: number[] = [], ys: number[] = []
    for (let i = 0; i <= 8; i++) for (let j = 0; j <= 8; j++) {
      const p = proj([w + ((e - w) * i) / 8, s + ((n - s) * j) / 8]); if (p) { xs.push(p[0]); ys.push(p[1]) }
    }
    const x0 = Math.min(...xs), x1 = Math.max(...xs), y0 = Math.min(...ys), y1 = Math.max(...ys)
    const k = Math.min(K_MAX, Math.max(1, 0.95 * Math.min(W / (x1 - x0), H / (y1 - y0))))
    animateTo(clampV({ k, x: W / 2 - ((x0 + x1) / 2) * k, y: H / 2 - ((y0 + y1) / 2) * k }))
  }
  const button = (f: number) => { setRegion(''); animateTo(zoomAround(viewRef.current, W / 2, H / 2, f)) }

  // Ctrl/⌘ + wheel (and trackpad pinch, which browsers report as ctrl+wheel) zooms; a plain wheel keeps scrolling the page.
  useEffect(() => {
    const el = svg.current
    if (!el || !zoom) return
    let t: any
    const onWheel = (e: WheelEvent) => {
      if (!(e.ctrlKey || e.metaKey)) { setHint(true); clearTimeout(t); t = setTimeout(() => setHint(false), 1400); return }
      e.preventDefault()
      cancelAnimationFrame(anim.current)
      const [sx, sy] = toSvg(e.clientX, e.clientY)
      setRegion('')
      setView(v => zoomAround(v, sx, sy, Math.exp(-e.deltaY * 0.0022)))
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => { el.removeEventListener('wheel', onWheel); clearTimeout(t) }
  }, [zoom]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => () => cancelAnimationFrame(anim.current), [])

  const onPointerDown = (e: React.PointerEvent) => {
    if (!zoom || e.button !== 0 || viewRef.current.k <= 1.001) return
    cancelAnimationFrame(anim.current)
    drag.current = { px: e.clientX, py: e.clientY, v: viewRef.current, moved: false }
  }
  const onPointerMove = (e: React.PointerEvent) => {
    const d = drag.current
    if (wrap.current && !d) {
      // tooltip position relative to the map box
      const r = wrap.current.getBoundingClientRect()
      if (hover) setHover(h => (h ? { ...h, x: e.clientX - r.left, y: e.clientY - r.top } : h))
    }
    if (!d) return
    const dx = e.clientX - d.px, dy = e.clientY - d.py
    if (!d.moved && Math.hypot(dx, dy) < 4) return
    if (!d.moved) { d.moved = true; setDragging(true); setHover(null); (e.currentTarget as Element).setPointerCapture?.(e.pointerId) }
    const m = svg.current?.getScreenCTM()
    const s = m ? m.a : 1 // screen pixels per SVG unit
    setView(clampV({ k: d.v.k, x: d.v.x + dx / s, y: d.v.y + dy / s }))
    setRegion('')
  }
  const onPointerUp = () => {
    if (drag.current?.moved) { suppressClick.current = true; setTimeout(() => (suppressClick.current = false), 0) }
    drag.current = null; setDragging(false)
  }
  const onDoubleClick = (e: React.MouseEvent) => {
    if (!zoom) return
    const [sx, sy] = toSvg(e.clientX, e.clientY)
    setRegion('')
    animateTo(zoomAround(viewRef.current, sx, sy, e.shiftKey ? 0.5 : 2))  // Shift + double-click zooms out
  }
  const at = (e: React.MouseEvent) => {
    const r = wrap.current?.getBoundingClientRect()
    return r ? { x: e.clientX - r.left, y: e.clientY - r.top } : { x: 0, y: 0 }
  }

  const fill = (name: string) => {
    if (!choropleth) return undefined
    const a2 = n2a[name]
    const v = a2 ? choropleth[a2] || 0 : 0
    if (!v) return undefined
    const i = Math.min(BLUE_RAMP.length - 1, Math.floor((Math.log(v + 1) / Math.log(max + 1)) * (BLUE_RAMP.length - 1)))
    return BLUE_RAMP[i]
  }
  const order = { low: 0, medium: 1, high: 2, critical: 3 } as Record<string, number>
  const k = view.k
  const inView = zoom && k > 1.001 ? placed.filter(p => { const x = p.x * k + view.x, y = p.y * k + view.y; return x >= 0 && x <= W && y >= 0 && y <= H }).length : placed.length
  const ww = wrap.current?.clientWidth || 800

  return (
    <div ref={wrap} className="map-wrap" style={{ height }} onMouseLeave={() => { setHover(null); onPointerUp() }}>
      <svg ref={svg} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" style={{ height: height || 'auto', touchAction: k > 1.001 ? 'none' : 'pan-y' }}
        className={dragging ? 'dragging' : zoom && k > 1.001 ? 'pannable' : undefined}
        onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp} onPointerCancel={onPointerUp} onDoubleClick={onDoubleClick}>
        <g transform={`translate(${view.x} ${view.y}) scale(${k})`}>
          <path d={grat || ''} className="map-grat" vectorEffect="non-scaling-stroke" />
          {countries.map((f: any) => (
            <path key={f.id || f.properties.name} d={path(f) || ''} className="map-land" vectorEffect="non-scaling-stroke"
              style={{ fill: fill(f.properties.name), cursor: onCountry && n2a[f.properties.name] ? 'pointer' : undefined }}
              onMouseMove={e => choropleth && !drag.current?.moved && setHover({ ...at(e), country: f.properties.name, n: choropleth[n2a[f.properties.name]] || 0 })}
              onClick={() => !suppressClick.current && onCountry && n2a[f.properties.name] && onCountry(n2a[f.properties.name])} />
          ))}
          {[...placed].sort((a, b) => (order[a.level || 'low'] || 0) - (order[b.level || 'low'] || 0)).map(p => {
            const c = SEV_COLOR[p.level || 'low'] || SERIES[0]
            // on screen, markers grow by a quarter per doubling of zoom (not with the map), so clusters separate as you zoom in
            const r = ((p.level === 'critical' ? 4.5 : p.level === 'high' ? 4 : 3.2) * (1 + 0.25 * Math.log2(k))) / k
            return (
              <g key={p.id} style={{ cursor: p.onClick ? 'pointer' : 'default' }} onClick={() => !suppressClick.current && p.onClick?.()}
                onMouseMove={e => !drag.current?.moved && setHover({ ...at(e), p })}>
                {p.pulse && <circle cx={p.x} cy={p.y} r={r} fill="none" stroke={c} strokeWidth={1.5 / k} className="ping" />}
                <circle cx={p.x} cy={p.y} r={12 / k} fill="transparent" />
                <circle cx={p.x} cy={p.y} r={r} fill={c} stroke={SURFACE} strokeWidth={1.5 / k} />
              </g>
            )
          })}
        </g>
      </svg>
      {zoom && (
        <>
          {(height ?? 440) >= 320 && (  // small maps keep only the zoom buttons
            <div className="map-regions">
              {REGIONS.map(r => <button key={r.id} className={region === r.id ? 'on' : undefined} onClick={() => goRegion(r.id)}>{r.label}</button>)}
            </div>)}
          <div className="map-ctrl">
            <button title="Zoom in" aria-label="Zoom in" onClick={() => button(2)} disabled={k >= K_MAX - 0.01}><Plus size={14} /></button>
            <button title="Zoom out" aria-label="Zoom out" onClick={() => button(0.5)} disabled={k <= 1.001}><Minus size={14} /></button>
            <button title="Reset to world view" aria-label="Reset" onClick={() => goRegion('world')} disabled={k <= 1.001}><RotateCcw size={13} /></button>
          </div>
          <div className="map-hint">
            {hint ? 'Hold Ctrl (⌘ on Mac) and scroll to zoom' : k > 1.001 ? `${Math.round(k * 10) / 10}× · drag to pan · ${inView} of ${placed.length} markers in view` : 'Double-click, Ctrl + scroll or pick a region to zoom'}
          </div>
        </>
      )}
      {hover && (hover.p || hover.country) && (
        <div className="tip" style={{ position: 'absolute', left: Math.max(4, Math.min(hover.x + 14, ww - 250)), top: hover.y + 12, pointerEvents: 'none' }}>
          {hover.p ? (<><strong>{hover.p.label}</strong>{hover.p.sub && <div>{hover.p.sub}</div>}{(hover.p as any).approx && <div className="muted">Location: country level</div>}</>)
            : (<><strong>{hover.n}</strong> · {hover.country}</>)}
        </div>
      )}
    </div>
  )
}
