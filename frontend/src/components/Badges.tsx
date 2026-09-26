import type { AlertStatus, Severity } from '../types'

const SEV_STYLES: Record<Severity, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
}

const STATUS_STYLES: Record<AlertStatus, string> = {
  NEW: 'bg-cinder-panel text-cinder-muted border-cinder-border',
  INVESTIGATING: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  CONFIRMED: 'bg-red-500/15 text-red-400 border-red-500/30',
  CLOSED: 'bg-cinder-panel text-cinder-muted border-cinder-border',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold border ${SEV_STYLES[severity]}`}
    >
      {severity}
    </span>
  )
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium border ${STATUS_STYLES[status]}`}
    >
      {status}
    </span>
  )
}

export function TypeChip({ type }: { type: string }) {
  return (
    <span className="inline-flex items-center rounded bg-cinder-panel border border-cinder-border px-2 py-0.5 text-[11px] text-cinder-muted">
      {type.replaceAll('_', ' ')}
    </span>
  )
}