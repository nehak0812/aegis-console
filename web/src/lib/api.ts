import { useQuery, keepPreviousData } from '@tanstack/react-query'

export type Level = 'critical' | 'high' | 'medium' | 'low'

/** FastAPI puts the reason in the body: a string for HTTPException, a list of
 *  {loc, msg} for request-validation errors. statusText is always empty over
 *  HTTP/2, so without this the caller only ever sees a bare status code. */
function reason(body: any): string {
  const d = body?.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d)) return d.map((e: any) => e?.msg).filter(Boolean).join('; ')
  return ''
}

export async function api<T = any>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`/api${path}`, init)
  if (!r.ok) {
    let detail = ''
    try { detail = reason(await r.json()) } catch { /* not JSON — fall back to the status */ }
    throw new Error(detail || `${r.status}${r.statusText ? ` ${r.statusText}` : ''}`)
  }
  return r.json()
}

/** Live query: refetches every `every` seconds, holds the previous render while refetching (no flash). */
export function useApi<T = any>(path: string | null, every = 60) {
  return useQuery<T>({
    queryKey: [path],
    queryFn: () => api<T>(path as string),
    enabled: !!path,
    refetchInterval: every * 1000,
    placeholderData: keepPreviousData,
    staleTime: 20_000,
  })
}

/** Arrays become repeated keys (?sector=A&sector=B), which is what the multi-select filters send. */
export function qs(params: Record<string, string | number | undefined | null | boolean | string[]>) {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (Array.isArray(v)) v.forEach(item => item !== '' && u.append(k, item))
    else if (v !== undefined && v !== null && v !== '' && v !== false) u.set(k, String(v))
  }
  const s = u.toString()
  return s ? `?${s}` : ''
}
