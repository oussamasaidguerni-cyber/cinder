import type { Stats } from '../types'

interface Kpi {
  label: string
  value: number
  tone: 'critical' | 'high' | 'medium' | 'low' | 'plain'
}

function kpis(s: Stats): Kpi[] {
  return [
    { label: 'Critical', value: s.critical, tone: 'critical' },
    { label: 'High', value: s.high, tone: 'high' },
    { label: 'Medium', value: s.medium, tone: 'medium' },
    { label: 'Low', value: s.low, tone: 'low' },
  ]
}

const TONE_TEXT: Record<Kpi['tone'], string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-sky-400',
  plain: 'text-cinder-text',
}

export function KpiCards({ stats }: { stats: Stats | null }) {
  if (!stats) return null
  const items = kpis(stats)
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
        <div className="text-[11px] uppercase tracking-wider text-cinder-muted">Total alerts</div>
        <div className="mt-1 text-2xl font-semibold">{stats.total}</div>
      </div>
      {items.map((k) => (
        <div key={k.label} className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
          <div className="text-[11px] uppercase tracking-wider text-cinder-muted">{k.label}</div>
          <div className={`mt-1 text-2xl font-semibold ${TONE_TEXT[k.tone]}`}>{k.value}</div>
        </div>
      ))}
    </div>
  )
}

export function SeverityDistribution({ stats }: { stats: Stats | null }) {
  if (!stats || stats.total === 0) return null
  const entries: [string, number, string][] = [
    ['CRITICAL', stats.critical, 'bg-red-500'],
    ['HIGH', stats.high, 'bg-orange-500'],
    ['MEDIUM', stats.medium, 'bg-yellow-500'],
    ['LOW', stats.low, 'bg-sky-500'],
  ]
  return (
    <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
      <div className="mb-3 text-[11px] uppercase tracking-wider text-cinder-muted">
        Severity distribution
      </div>
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-cinder-bg">
        {entries.map(([label, count, cls]) =>
          count > 0 ? (
            <div
              key={label}
              className={`${cls} h-full`}
              style={{ width: `${(count / stats.total) * 100}%` }}
              title={`${label}: ${count}`}
            />
          ) : null,
        )}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-cinder-muted">
        {entries.map(([label, count, cls]) => (
          <span key={label} className="inline-flex items-center gap-1.5">
            <span className={`h-2 w-2 rounded-sm ${cls}`} />
            {label} · {count}
          </span>
        ))}
      </div>
    </div>
  )
}

export function StatusDistribution({ stats }: { stats: Stats | null }) {
  if (!stats) return null
  const names = Object.keys(stats.by_status)
  if (names.length === 0) return null
  return (
    <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
      <div className="mb-3 text-[11px] uppercase tracking-wider text-cinder-muted">Alert status</div>
      <div className="flex flex-col gap-2">
        {names.map((name) => (
          <div key={name} className="flex items-center justify-between text-sm">
            <span className="text-cinder-muted">{name}</span>
            <span className="font-mono text-cinder-text">{stats.by_status[name]}</span>
          </div>
        ))}
      </div>
    </div>
  )
}