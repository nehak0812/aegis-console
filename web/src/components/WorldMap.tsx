import { useMemo, useState, useRef, useEffect, useCallback } from 'react'
import type { MouseEvent as RMouseEvent, PointerEvent as RPointerEvent } from 'react'
import { ZoomIn, ZoomOut, Maximize2 } from 'lucide-react'
import { geoNaturalEarth1, geoPath, geoGraticule10, geoCentroid } from 'd3-geo'
import { feature } from 'topojson-client'
import world from 'world-atlas/countries-110m.json'
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
const MAX_K = 8

export default function WorldMap({ points = [], choropleth, height, zoomable, onCountry }: { points?: MapPoint[]; choropleth?: Record<string, number>; height?: number; zoomable?: boolean; onCountry?: (a2: string) => void }) {
  const [hover, setHover] = useState<{ x: number; y: number; p?: MapPoint; country?: string; n?: number } | null>(null)
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

  const fill = (name: string) => {
    if (!choropleth) return undefined
    const a2 = n2a[name]
    const v = a2 ? choropleth[a2] || 0 : 0
    if (!v) return undefined
    const i = Math.min(BLUE_RAMP.length - 1, Math.floor((Math.log(v + 1) / Math.log(max + 1)) * (BLUE_RAMP.length - 1)))
    return BLUE_RAMP[i]
  }
  const order = { low: 0, medium: 1, high: 2, critical: 3 } as Record<string, number>

  // ---- zoom & pan · opt-in, so the small choropleth cards stay static ----
  const wrapRef = useRef<HTMLDivElement>(null)
  const svgRef = useRef<SVGSVGElement>(null)
  const [zoom, setZoom] = useState({ k: 1, x: 0, y: 0 })
  const [grabbing, setGrabbing] = useState(false)
  const drag = useRef<{ vx: number; vy: number; x: number; y: number } | null>(null)
  const moved = useRef(false)
  const captured = useRef(false)

  // keep the map covering the frame: at k=1 there is nothing to pan to
  const clamp = (z: { k: number; x: number; y: number }) => {
    const k = Math.max(1, Math.min(MAX_K, z.k))
    return { k, x: Math.max(W * (1 - k), Math.min(0, z.x)), y: Math.max(H * (1 - k), Math.min(0, z.y)) }
  }
  // client pixels → viewBox units, honouring preserveAspectRatio letterboxing
  const toVB = useCallback((cx: number, cy: number): [number, number] | null => {
    const ctm = svgRef.current?.getScreenCTM()
    if (!ctm) return null
    const p = new DOMPoint(cx, cy).matrixTransform(ctm.inverse())
    return [p.x, p.y]
  }, [])
  const zoomBy = useCallback((factor: number, cx?: number, cy?: number) => {
    setZoom(z => {
      const k = Math.max(1, Math.min(MAX_K, z.k * factor))
      const c = (cx != null && cy != null ? toVB(cx, cy) : null) || [W / 2, H / 2]
      // hold whatever is under the cursor still
      return clamp({ k, x: c[0] - (k / z.k) * (c[0] - z.x), y: c[1] - (k / z.k) * (c[1] - z.y) })
    })
  }, [toVB])
  const reset = () => setZoom({ k: 1, x: 0, y: 0 })

  // React's onWheel is passive, so it cannot preventDefault the page scroll
  useEffect(() => {
    const el = svgRef.current
    if (!zoomable || !el) return
    const h = (e: WheelEvent) => { e.preventDefault(); zoomBy(e.deltaY < 0 ? 1.2 : 1 / 1.2, e.clientX, e.clientY) }
    el.addEventListener('wheel', h, { passive: false })
    return () => el.removeEventListener('wheel', h)
  }, [zoomable, zoomBy])

  const onDown = (e: RPointerEvent<SVGSVGElement>) => {
    if (!zoomable) return
    const v = toVB(e.clientX, e.clientY)
    if (!v) return
    moved.current = false
    drag.current = { vx: v[0], vy: v[1], x: zoom.x, y: zoom.y }
    setGrabbing(true)
  }
  const onDrag = (e: RPointerEvent<SVGSVGElement>) => {
    const d = drag.current
    if (!d) return
    const v = toVB(e.clientX, e.clientY)
    if (!v) return
    // a real drag suppresses the click, so panning never opens an organisation
    if (Math.abs(v[0] - d.vx) > 1.5 || Math.abs(v[1] - d.vy) > 1.5) {
      moved.current = true
      // capture only once panning actually starts: capturing on pointerdown would
      // retarget the click to the <svg> and a plain click would never reach a marker
      if (!captured.current) { e.currentTarget.setPointerCapture?.(e.pointerId); captured.current = true }
    }
    setZoom(z => clamp({ k: z.k, x: d.x + (v[0] - d.vx), y: d.y + (v[1] - d.vy) }))
  }
  const onUp = (e: RPointerEvent<SVGSVGElement>) => {
    if (captured.current) { e.currentTarget.releasePointerCapture?.(e.pointerId); captured.current = false }
    drag.current = null
    setGrabbing(false)
  }

  // tooltip coords are CSS pixels inside the wrapper, so they stay right when zoomed
  const at = (e: RMouseEvent) => {
    const r = wrapRef.current?.getBoundingClientRect()
    return r ? { x: e.clientX - r.left, y: e.clientY - r.top } : { x: 0, y: 0 }
  }
  const tipMax = (wrapRef.current?.clientWidth || W) - 190
  const inv = 1 / zoom.k

  return (
    <div ref={wrapRef} className={`map-wrap${zoomable ? ' zoomable' : ''}${grabbing ? ' grabbing' : ''}`} style={{ height }} onMouseLeave={() => setHover(null)}>
      <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" style={{ height: height || 'auto' }}
        onPointerDown={onDown} onPointerMove={onDrag} onPointerUp={onUp} onPointerCancel={onUp}
        onDoubleClick={e => { if (zoomable) zoomBy(1.6, e.clientX, e.clientY) }}>
        <g transform={`translate(${zoom.x} ${zoom.y}) scale(${zoom.k})`}>
          <path d={grat || ''} className="map-grat" vectorEffect="non-scaling-stroke" />
          {countries.map((f: any) => (
            <path key={f.id || f.properties.name} d={path(f) || ''} className="map-land" vectorEffect="non-scaling-stroke"
              style={{ fill: fill(f.properties.name), cursor: onCountry && n2a[f.properties.name] ? 'pointer' : undefined }}
              onMouseMove={e => choropleth && setHover({ ...at(e), country: f.properties.name, n: choropleth[n2a[f.properties.name]] || 0 })}
              onClick={() => { if (!moved.current && onCountry && n2a[f.properties.name]) onCountry(n2a[f.properties.name]) }} />
          ))}
          {[...placed].sort((a, b) => (order[a.level || 'low'] || 0) - (order[b.level || 'low'] || 0)).map(p => {
            const c = SEV_COLOR[p.level || 'low'] || SERIES[0]
            // markers keep a constant on-screen size as the map scales
            const r = (p.level === 'critical' ? 4.5 : p.level === 'high' ? 4 : 3.2) * inv
            return (
              <g key={p.id} style={{ cursor: p.onClick ? 'pointer' : 'default' }} onClick={() => { if (!moved.current) p.onClick?.() }}
                onMouseMove={e => setHover({ ...at(e), p })}>
                {p.pulse && <circle cx={p.x} cy={p.y} r={r} fill="none" stroke={c} strokeWidth={1.5 * inv} className="ping" />}
                <circle cx={p.x} cy={p.y} r={12 * inv} fill="transparent" />
                <circle cx={p.x} cy={p.y} r={r} fill={c} stroke={SURFACE} strokeWidth={1.5 * inv} />
              </g>
            )
          })}
        </g>
      </svg>
      {zoomable && (
        <>
          <div className="map-zoom">
            <button className="btn" title="Zoom in" aria-label="Zoom in" disabled={zoom.k >= MAX_K} onClick={() => zoomBy(1.6)}><ZoomIn size={14} /></button>
            <button className="btn" title="Zoom out" aria-label="Zoom out" disabled={zoom.k <= 1} onClick={() => zoomBy(1 / 1.6)}><ZoomOut size={14} /></button>
            <button className="btn" title="Reset view" aria-label="Reset view" disabled={zoom.k === 1 && zoom.x === 0 && zoom.y === 0} onClick={reset}><Maximize2 size={14} /></button>
          </div>
          <div className="map-hint">scroll to zoom · drag to pan{zoom.k > 1 ? ` · ${zoom.k.toFixed(1)}×` : ''}</div>
        </>
      )}
      {hover && (hover.p || hover.country) && (
        <div className="tip" style={{ position: 'absolute', left: Math.min(hover.x + 14, tipMax), top: hover.y + 10, pointerEvents: 'none' }}>
          {hover.p ? (<><strong>{hover.p.label}</strong>{hover.p.sub && <div>{hover.p.sub}</div>}{(hover.p as any).approx && <div className="muted">Location: country level</div>}</>)
            : (<><strong>{hover.n}</strong> · {hover.country}</>)}
        </div>
      )}
    </div>
  )
}
