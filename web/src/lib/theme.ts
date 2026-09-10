import { applyChartTheme, ThemeName } from './chartTheme'

const KEY = 'aegis-theme'

export function initialTheme(): ThemeName {
  try {  // ?theme=light|dim|dark in the URL wins (shareable), then the saved choice, then the OS preference
    const q = new URLSearchParams(window.location.search).get('theme')
    if (q === 'dark' || q === 'dim' || q === 'light') return q
  } catch { /* ignore */ }
  try {
    const t = localStorage.getItem(KEY)
    if (t === 'dark' || t === 'dim' || t === 'light') return t
  } catch { /* storage unavailable */ }
  try { return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark' } catch { return 'dark' }
}

export function applyTheme(t: ThemeName, persist = true) {
  document.documentElement.dataset.theme = t
  applyChartTheme(t)
  if (persist) { try { localStorage.setItem(KEY, t) } catch { /* ignore */ } }
}
