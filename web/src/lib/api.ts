import { useQuery, keepPreviousData } from '@tanstack/react-query'

export type Level = 'critical' | 'high' | 'medium' | 'low'

export async function api<T = any>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`/api${path}`, init)
  if (!r.ok) {
    let detail = ''
    try { detail = (await r.json()).detail } catch { /* not JSON */ }
    throw new Error(detail || `${r.status} ${r.statusText}`)  // the API explains rejected actions; show that, not just the code
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
    if (Array.isArray(v)) { v.forEach(item => item !== '' && u.append(k, item)); continue }
    if (v !== undefined && v !== null && v !== '' && v !== false) u.set(k, String(v))
  }
  const s = u.toString()
  return s ? `?${s}` : ''
}
