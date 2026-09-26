import { useEffect, useState } from 'react'
import { api } from '../api'
import type { AlertStatus, AlertSummary, AnalysisResult, Severity } from '../types'
import { SeverityBadge, StatusBadge, TypeChip } from './Badges'

interface Props {
  onOpen: (id: string) => void
  refreshKey: number
}

const SEVERITY_FILTERS: (Severity | 'ALL')[] = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const STATUS_FILTERS: (AlertStatus | 'ALL')[] = ['ALL', 'NEW', 'INVESTIGATING', 'CONFIRMED', 'CLOSED']

function formatTime(iso: string): string {
  try {
    const then = new Date(iso).getTime()
    const diff = Math.max(0, Date.now() - then)
    const min = Math.floor(diff / 60000)
    if (min < 1) return 'just now'
    if (min < 60) return `${min}m ago`
    const hr = Math.floor(min / 60)
    if (hr < 24) return `${hr}h ${min % 60}m ago`
    const day = Math.floor(hr / 24)
    return `${day}d ago`
  } catch {
    return iso
  }
}

function AiChip({ result }: { result: AnalysisResult | undefined }) {
  if (!result) return null
  const severityColor =
    result.severity === 'CRITICAL' || result.severity === 'HIGH'
      ? 'text-red-400'
      : result.severity === 'MEDIUM'
        ? 'text-yellow-400'
        : 'text-sky-400'
  return (
    <div className="flex flex-col gap-0.5">
      <span className={`inline-flex items-center gap-1 text-[10px] font-medium ${severityColor}`}>
        <span className="h-1.5 w-1.5 rounded-full bg-current" />
        {result.threat_type}
      </span>
      <span className="text-[9px] text-cinder-muted">
        {result.analysis_mode === 'ai' ? 'AI' : 'fallback'} · {result.confidence}%
      </span>
    </div>
  )
}

export function AlertTable({ onOpen, refreshKey }: Props) {
  const [alerts, setAlerts] = useState<AlertSummary[]>([])
  const [analyses, setAnalyses] = useState<Record<string, AnalysisResult>>({})
  const [severity, setSeverity] = useState<Severity | 'ALL'>('ALL')
  const [status, setStatus] = useState<AlertStatus | 'ALL'>('ALL')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [, setTick] = useState(0)

  useEffect(() => {
    const timer = window.setInterval(() => setTick((t) => t + 1), 30000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    api
      .alerts(severity === 'ALL' ? undefined : severity, status === 'ALL' ? undefined : status)
      .then((rows) => {
        if (!cancelled) setAlerts(rows)
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Failed to load alerts')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [severity, status, refreshKey])

  useEffect(() => {
    let cancelled = false
    setScanning(true)
    api
      .analyzeAll()
      .then((items) => {
        if (!cancelled) {
          const map: Record<string, AnalysisResult> = {}
          items.forEach((i) => {
            map[i.alert_id] = i.result
          })
          setAnalyses(map)
        }
      })
      .catch(() => {
        /* non-fatal: chips simply don't appear */
      })
      .finally(() => {
        if (!cancelled) setScanning(false)
      })
    return () => {
      cancelled = true
    }
  }, [refreshKey])

  return (
    <div className="rounded-lg border border-cinder-border bg-cinder-panel">
      <div className="flex flex-wrap items-center gap-3 border-b border-cinder-border p-4">
        <div className="flex gap-1">
          {SEVERITY_FILTERS.map((s) => (
            <button
              key={s}
              onClick={() => setSeverity(s)}
              className={`rounded px-2.5 py-1 text-xs font-medium ${
                severity === s
                  ? 'bg-cinder-text text-cinder-bg'
                  : 'bg-cinder-bg text-cinder-muted hover:text-cinder-text'
              }`}
            >
              {s === 'ALL' ? 'All' : s}
            </button>
          ))}
        </div>
        <div className="flex gap-1">
          {STATUS_FILTERS.map((s) => (
            <button
              key={s}
              onClick={() => setStatus(s)}
              className={`rounded px-2.5 py-1 text-xs font-medium ${
                status === s
                  ? 'bg-cinder-text text-cinder-bg'
                  : 'bg-cinder-bg text-cinder-muted hover:text-cinder-text'
              }`}
            >
              {s === 'ALL' ? 'All' : s}
            </button>
          ))}
        </div>
        <span className="ml-auto flex items-center gap-2 text-xs text-cinder-muted">
          {scanning && Object.keys(analyses).length === 0 ? (
            <>
              <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />
              Scanning with CINDER AI…
            </>
          ) : (
            <>
              <span className="h-2 w-2 rounded-full bg-emerald-400/40" />
              AI status ready
            </>
          )}
        </span>
      </div>

      {loading ? (
        <div className="p-8 text-center text-sm text-cinder-muted">Loading alerts…</div>
      ) : error ? (
        <div className="p-8 text-center text-sm text-red-400">{error}</div>
      ) : alerts.length === 0 ? (
        <div className="p-8 text-center text-sm text-cinder-muted">
          No alerts match the current filters.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="text-[11px] uppercase tracking-wider text-cinder-muted">
                <th className="px-4 py-2 font-medium">Alert ID</th>
                <th className="px-4 py-2 font-medium">Time</th>
                <th className="px-4 py-2 font-medium">Source</th>
                <th className="px-4 py-2 font-medium">Source IP</th>
                <th className="px-4 py-2 font-medium hidden md:table-cell">Destination</th>
                <th className="px-4 py-2 font-medium">Type</th>
                <th className="px-4 py-2 font-medium">Severity</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">CINDER AI</th>
                <th className="px-4 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr
                  key={a.id}
                  onClick={() => onOpen(a.id)}
                  className="cursor-pointer border-t border-cinder-border/60 hover:bg-cinder-bg/60"
                >
                  <td className="px-4 py-2.5 font-mono text-xs text-cinder-text">{a.id}</td>
                  <td className="px-4 py-2.5 whitespace-nowrap text-cinder-muted" title={new Date(a.timestamp).toLocaleString()}>
                    {formatTime(a.timestamp)}
                  </td>
                  <td className="px-4 py-2.5">{a.source}</td>
                  <td className="px-4 py-2.5 font-mono text-xs">{a.source_ip}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-cinder-muted hidden md:table-cell">{a.destination}</td>
                  <td className="px-4 py-2.5">
                    <TypeChip type={a.alert_type} />
                  </td>
                  <td className="px-4 py-2.5">
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td className="px-4 py-2.5">
                    <StatusBadge status={a.status} />
                  </td>
                  <td className="px-4 py-2.5">
                    <AiChip result={analyses[a.id]} />
                  </td>
                  <td className="px-4 py-2.5 text-right text-cinder-muted">→</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}