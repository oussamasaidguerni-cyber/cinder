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

export function DataKindBadge({ kind }: { kind: string }) {
  if (kind === 'live') {
    return (
      <span className="inline-flex items-center rounded border border-emerald-500/30 bg-emerald-500/15 px-2 py-0.5 text-[11px] font-semibold text-emerald-400">
        ● LIVE
      </span>
    )
  }
  if (kind === 'cached') {
    return (
      <span className="inline-flex items-center rounded border border-sky-500/30 bg-sky-500/15 px-2 py-0.5 text-[11px] font-semibold text-sky-400">
        ◐ CACHED
      </span>
    )
  }
  if (kind === 'synthetic')
    return (
      <span className="inline-flex items-center rounded border border-yellow-500/30 bg-yellow-500/15 px-2 py-0.5 text-[11px] font-semibold text-yellow-400">
        ⚠ SYNTHETIC
      </span>
    )
  return (
    <span className="inline-flex items-center rounded border border-cinder-border bg-cinder-panel px-2 py-0.5 text-[11px] text-cinder-muted">
      {kind}
    </span>
  )
}

export function KevStatusPill({ status }: { status: string }) {
  if (status === 'IN_KEV') {
    return (
      <span
        className="inline-flex items-center rounded border border-red-500/40 bg-red-500/15 px-2 py-0.5 text-[11px] font-bold text-red-400"
        title="Known Exploited Vulnerabilities catalog"
      >
        EXPLOITED IN THE WILD (CISA)
      </span>
    )
  }
  if (status === 'UNKNOWN')
    return (
      <span className="inline-flex items-center rounded border border-cinder-border bg-cinder-panel px-2 py-0.5 text-[11px] text-cinder-muted">
        KEV status unknown
      </span>
    )
  return (
    <span className="inline-flex items-center rounded border border-cinder-border bg-cinder-panel px-2 py-0.5 text-[11px] text-cinder-muted">
      Not in KEV catalog
    </span>
  )
}