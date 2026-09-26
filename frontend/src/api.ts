import type {
  Alert,
  AlertStatus,
  AlertSummary,
  AnalysisResult,
  AskResponse,
  BatchAnalysisItem,
  Health,
  Severity,
  Stats,
} from './types'

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json() as Promise<T>
}

async function post<T>(url: string, body?: unknown): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json() as Promise<T>
}

async function patch<T>(url: string, body?: unknown): Promise<T> {
  const res = await fetch(url, {
    method: 'PATCH',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json() as Promise<T>
}

export const api = {
  health: () => get<Health>('/health'),
  alerts: (severity?: Severity, status?: AlertStatus) => {
    const params = new URLSearchParams()
    if (severity) params.set('severity', severity)
    if (status) params.set('status', status)
    const qs = params.toString()
    return get<AlertSummary[]>(`/alerts${qs ? `?${qs}` : ''}`)
  },
  stats: () => get<Stats>('/alerts/stats'),
  alert: (id: string) => get<Alert>(`/alerts/${id}`),
  analyze: (id: string) => post<AnalysisResult>(`/alerts/${id}/analyze`),
  analyzeAll: () => get<BatchAnalysisItem[]>('/alerts/analyze-all'),
  analyzeRaw: (text: string) => post<AnalysisResult>('/alerts/analyze-raw', { text }),
  simulate: () => post<Alert>('/alerts/simulate'),
  updateStatus: (id: string, status: AlertStatus) =>
    patch<Alert>(`/alerts/${id}/status`, { status }),
  ask: (id: string, question: string) =>
    post<AskResponse>(`/alerts/${id}/ask`, { question }),
}