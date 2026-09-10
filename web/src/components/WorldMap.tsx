import { useMemo, useState } from 'react'
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

export default function WorldMap({ points = [], choropleth, height, onCountry }: { points?: MapPoint[]; choropleth?: Record<string, number>; height?: number; onCountry?: (a2: string) => void }) {
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

  return (
    <div className="map-wrap" style={{ height }} onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" style={{ height: height || 'auto' }}>
        <path d={grat || ''} className="map-grat" />
        {countries.map((f: any) => (
          <path key={f.id || f.properties.name} d={path(f) || ''} className="map-land" style={{ fill: fill(f.properties.name), cursor: onCountry && n2a[f.properties.name] ? 'pointer' : undefined }}
            onMouseMove={e => choropleth && setHover({ x: e.nativeEvent.offsetX, y: e.nativeEvent.offsetY, country: f.properties.name, n: choropleth[n2a[f.properties.name]] || 0 })}
            onClick={() => onCountry && n2a[f.properties.name] && onCountry(n2a[f.properties.name])} />
        ))}
        {[...placed].sort((a, b) => (order[a.level || 'low'] || 0) - (order[b.level || 'low'] || 0)).map(p => {
          const c = SEV_COLOR[p.level || 'low'] || SERIES[0]
          const r = p.level === 'critical' ? 4.5 : p.level === 'high' ? 4 : 3.2
          return (
            <g key={p.id} style={{ cursor: p.onClick ? 'pointer' : 'default' }} onClick={p.onClick}
              onMouseMove={e => setHover({ x: e.nativeEvent.offsetX, y: e.nativeEvent.offsetY, p })}>
              {p.pulse && <circle cx={p.x} cy={p.y} r={r} fill="none" stroke={c} strokeWidth={1.5} className="ping" />}
              <circle cx={p.x} cy={p.y} r={12} fill="transparent" />
              <circle cx={p.x} cy={p.y} r={r} fill={c} stroke={SURFACE} strokeWidth={1.5} />
            </g>
          )
        })}
      </svg>
      {hover && (hover.p || hover.country) && (
        <div className="tip" style={{ position: 'absolute', left: Math.min(hover.x + 14, 700), top: hover.y + 10, pointerEvents: 'none' }}>
          {hover.p ? (<><strong>{hover.p.label}</strong>{hover.p.sub && <div>{hover.p.sub}</div>}{(hover.p as any).approx && <div className="muted">Location: country level</div>}</>)
            : (<><strong>{hover.n}</strong> · {hover.country}</>)}
        </div>
      )}
    </div>
  )
}
