export function ago(ts?: string | null): string {
  if (!ts) return '—'
  const t = Date.parse(ts)
  if (isNaN(t)) return ts.slice(0, 10)
  const s = Math.max(0, (Date.now() - t) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  if (s < 86400 * 30) return `${Math.floor(s / 86400)}d ago`
  return new Date(t).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

export function day(ts?: string | null): string {
  if (!ts) return '—'
  const t = Date.parse(ts)
  if (isNaN(t)) return ts.slice(0, 10)
  return new Date(t).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

export function compact(n?: number | null): string {
  if (n === undefined || n === null) return '—'
  return new Intl.NumberFormat(undefined, { notation: n >= 10000 ? 'compact' : 'standard', maximumFractionDigits: 1 }).format(n)
}

export function host(url?: string | null): string {
  if (!url) return ''
  try { return new URL(url).hostname.replace(/^www\./, '') } catch { return '' }
}

export function pct(v?: number | null, digits = 1): string {
  if (v === undefined || v === null) return '—'
  return `${(v * 100).toFixed(digits)}%`
}

export const COUNTRY: Record<string, string> = {
  US: 'United States', GB: 'United Kingdom', DE: 'Germany', FR: 'France', NL: 'Netherlands', CH: 'Switzerland', ES: 'Spain', IT: 'Italy',
  IE: 'Ireland', SE: 'Sweden', NO: 'Norway', DK: 'Denmark', FI: 'Finland', BE: 'Belgium', AT: 'Austria', CA: 'Canada', AU: 'Australia',
  JP: 'Japan', IN: 'India', BR: 'Brazil', MX: 'Mexico', LU: 'Luxembourg', PT: 'Portugal', PL: 'Poland', CN: 'China', KR: 'South Korea',
  SG: 'Singapore', IL: 'Israel', AE: 'UAE', SA: 'Saudi Arabia', ZA: 'South Africa', TW: 'Taiwan', HK: 'Hong Kong', RU: 'Russia',
  IR: 'Iran', KP: 'North Korea', UA: 'Ukraine', TR: 'Turkey', AR: 'Argentina', CO: 'Colombia', CL: 'Chile', NZ: 'New Zealand',
  VN: 'Vietnam', PS: 'Palestine', LB: 'Lebanon', SY: 'Syria', PK: 'Pakistan', KZ: 'Kazakhstan', BY: 'Belarus', VE: 'Venezuela',
  EG: 'Egypt', GE: 'Georgia', CZ: 'Czechia', GR: 'Greece', RO: 'Romania', HU: 'Hungary', SK: 'Slovakia', TH: 'Thailand',
  MY: 'Malaysia', ID: 'Indonesia', PH: 'Philippines', NG: 'Nigeria', KE: 'Kenya', MA: 'Morocco', PE: 'Peru', QA: 'Qatar',
  KW: 'Kuwait', BH: 'Bahrain', OM: 'Oman', JO: 'Jordan', IQ: 'Iraq', LK: 'Sri Lanka', BD: 'Bangladesh', NP: 'Nepal',
  HR: 'Croatia', RS: 'Serbia', BG: 'Bulgaria', SI: 'Slovenia', EE: 'Estonia', LV: 'Latvia', LT: 'Lithuania', IS: 'Iceland',
  CY: 'Cyprus', MT: 'Malta', DO: 'Dominican Republic', PR: 'Puerto Rico', EC: 'Ecuador', UY: 'Uruguay', CR: 'Costa Rica', PA: 'Panama',
}
export const countryName = (c?: string | null) => (c ? COUNTRY[c.toUpperCase()] || c : '—')
