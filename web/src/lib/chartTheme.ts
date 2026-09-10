// Chart tokens shared by Recharts and Nivo. Three themes; each categorical palette is validated against its own
// surface (dataviz validator): dark on #12161c, dim on #222938 (green stepped up for 3:1), light on #ffffff.
// Exports are ES live bindings — applyChartTheme() updates them and the app remounts pages to redraw.
export type ThemeName = 'dark' | 'dim' | 'light'

const DARK_SERIES = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767']
const PAL = {
  dark: {
    series: DARK_SERIES, surface: '#12161c', ink: '#e8edf3', ink2: '#aab4c0', muted: '#7b8694', grid: '#232a34', axis: '#2d3542',
    empty: '#1a1f27', tip: '#1e2430', tipBorder: '#2d3542', neutral: '#5b6675', cursor: 'rgba(255,255,255,0.04)',
    ramp: ['#0d366b', '#104281', '#184f95', '#1c5cab', '#256abf', '#2a78d6', '#3987e5', '#5598e7', '#6da7ec', '#86b6ef'],
  },
  dim: {
    series: ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#2e9b2e', '#9085e9', '#e66767'], surface: '#222938',
    ink: '#eef2f7', ink2: '#b9c3d1', muted: '#8a96a8', grid: '#323b4f', axis: '#43506a',
    empty: '#29313f', tip: '#2a3243', tipBorder: '#43506a', neutral: '#6b778c', cursor: 'rgba(255,255,255,0.05)',
    ramp: ['#184f95', '#1c5cab', '#256abf', '#2a78d6', '#3987e5', '#5598e7', '#6da7ec', '#86b6ef', '#9ec5f4', '#b7d3f6'],
  },
  light: {
    series: ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#4a3aa7', '#e34948'], surface: '#ffffff',
    ink: '#0f172a', ink2: '#475569', muted: '#64748b', grid: '#e8ebf0', axis: '#cfd6df',
    empty: '#f1f3f6', tip: '#ffffff', tipBorder: '#dfe3e9', neutral: '#94a3b8', cursor: 'rgba(15,23,42,0.05)',
    ramp: ['#cde2fb', '#b7d3f6', '#9ec5f4', '#86b6ef', '#6da7ec', '#5598e7', '#3987e5', '#2a78d6', '#256abf', '#1c5cab'],
  },
}

// status colours are fixed across themes and always paired with an icon + label
export const SEV_COLOR: Record<string, string> = { critical: '#d03b3b', high: '#ec835a', medium: '#fab219', low: '#7b8694' }
export const SEV_ORDER = ['critical', 'high', 'medium', 'low'] as const
export const SEV_LABEL: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }

export const SERIES: string[] = [...DARK_SERIES]
export const BLUE_RAMP: string[] = [...PAL.dark.ramp]
export let INK = PAL.dark.ink
export let INK2 = PAL.dark.ink2
export let MUTED = PAL.dark.muted
export let GRID = PAL.dark.grid
export let AXIS = PAL.dark.axis
export let SURFACE = PAL.dark.surface
export let EMPTY = PAL.dark.empty
export let NEUTRAL = PAL.dark.neutral
export let CURSOR = PAL.dark.cursor
export let THEME: ThemeName = 'dark'

function buildNivo(p: typeof PAL.dark) {
  return {
    background: 'transparent',
    text: { fontSize: 11, fill: p.ink2, fontFamily: 'system-ui, -apple-system, Segoe UI, sans-serif' },
    axis: {
      domain: { line: { stroke: p.axis, strokeWidth: 1 } },
      ticks: { line: { stroke: p.axis, strokeWidth: 1 }, text: { fill: p.muted, fontSize: 11 } },
      legend: { text: { fill: p.ink2, fontSize: 11 } },
    },
    grid: { line: { stroke: p.grid, strokeWidth: 1 } },
    legends: { text: { fill: p.ink2, fontSize: 11 } },
    labels: { text: { fill: p.ink, fontSize: 11 } },
    tooltip: { container: { background: p.tip, color: p.ink, fontSize: 12, borderRadius: 8, border: `1px solid ${p.tipBorder}`, boxShadow: '0 10px 30px rgba(0,0,0,.25)' } },
    crosshair: { line: { stroke: p.ink2, strokeWidth: 1, strokeOpacity: 0.5 } },
  }
}
export let nivoTheme = buildNivo(PAL.dark)
export let rcAxis = { stroke: PAL.dark.axis, tick: { fill: PAL.dark.muted, fontSize: 11 }, tickLine: false, axisLine: { stroke: PAL.dark.axis } }

export function applyChartTheme(t: ThemeName) {
  const p = PAL[t] || PAL.dark
  THEME = t
  SERIES.splice(0, SERIES.length, ...p.series)
  BLUE_RAMP.splice(0, BLUE_RAMP.length, ...p.ramp)
  INK = p.ink; INK2 = p.ink2; MUTED = p.muted; GRID = p.grid; AXIS = p.axis
  SURFACE = p.surface; EMPTY = p.empty; NEUTRAL = p.neutral; CURSOR = p.cursor
  nivoTheme = buildNivo(p)
  rcAxis = { stroke: p.axis, tick: { fill: p.muted, fontSize: 11 }, tickLine: false, axisLine: { stroke: p.axis } }
}

/** Text colour for a label placed *inside* a coloured fill — white or ink by the fill's luminance. */
export function onFill(hex?: string): string {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex || '')
  if (!m) return '#ffffff'
  const n = parseInt(m[1], 16)
  const lin = (c: number) => { c /= 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4) }
  const L = 0.2126 * lin((n >> 16) & 255) + 0.7152 * lin((n >> 8) & 255) + 0.0722 * lin(n & 255)
  return L > 0.36 ? '#0f172a' : '#ffffff'
}
