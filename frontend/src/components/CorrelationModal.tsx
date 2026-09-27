import { useEffect } from 'react'
import type { CorrelatedIncident } from '../types'
import { SeverityBadge } from './Badges'

interface Props {
  incident: CorrelatedIncident
  onClose: () => void
  onOpenAlert: (alertId: string) => void
}

const PHASE_TONES = [
  'border-red-500/40',
  'border-orange-500/40',
  'border-yellow-500/40',
  'border-sky-500/40',
]

export function CorrelationModal({ incident, onClose, onOpenAlert }: Props) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const modeLabel =
    incident.analysis_mode === 'ai'
      ? `Live AI (${incident.model_used ?? 'gemini'})`
      : incident.analysis_mode === 'fallback'
        ? 'Deterministic — no live AI'
        : 'Deterministic engine'

  const confidenceColor =
    incident.confidence >= 85 ? 'text-red-400' : incident.confidence >= 70 ? 'text-orange-400' : 'text-yellow-400'

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-xl border border-cinder-border bg-cinder-panel p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-1 flex items-center justify-between">
          <div className="text-lg font-semibold">
            {incident.incident_id} · Correlated incident
          </div>
          <button
            onClick={onClose}
            className="rounded border border-cinder-border px-2 py-0.5 text-xs text-cinder-muted hover:text-cinder-text"
          >
            Esc
          </button>
        </div>

        <div className="mb-5 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-cinder-muted">
          <span className="font-mono text-cinder-text">{incident.title}</span>
          <span
            className={`inline-flex items-center gap-1 font-mono text-base font-semibold ${confidenceColor}`}
          >
            {incident.confidence}%
            <span className="text-[10px] font-normal uppercase tracking-wider text-cinder-muted">
              confidence
            </span>
          </span>
          <span
            className={`text-[11px] ${
              incident.analysis_mode === 'ai' ? 'text-emerald-400' : 'text-yellow-400'
            }`}
          >
            {modeLabel}
          </span>
        </div>

        <div className="mb-5 flex flex-col gap-3">
          {incident.phases.map((p) => (
            <button
              key={p.alert_id}
              onClick={() => onOpenAlert(p.alert_id)}
              className={`flex flex-col gap-1 rounded-lg border bg-cinder-bg p-4 text-left transition hover:border-sky-500/50 ${PHASE_TONES[p.order - 1]}`}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="flex h-6 w-6 items-center justify-center rounded-md bg-red-500/15 font-mono text-xs font-bold text-red-400">
                  {p.order}
                </span>
                <span className="text-sm font-semibold text-cinder-text">{p.phase_name}</span>
                <SeverityBadge severity={p.severity} />
                <span className="hidden font-mono text-[11px] text-cinder-muted sm:inline">
                  {p.technique_id} · {p.technique_name}
                </span>
                <span className="ml-auto font-mono text-[11px] text-cinder-muted">
                  {p.alert_id}
                </span>
              </div>
              <div className="pl-8 text-[11px] text-cinder-muted">
                MITRE {p.technique_id} — {p.technique_name} ({p.tactic}) · conf {p.confidence}%
                ·{' '}
                {new Date(p.timestamp).toLocaleString()}
              </div>
              {p.evidence.length > 0 && (
                <pre className="mt-1 whitespace-pre-wrap pl-8 font-mono text-[11px] leading-relaxed text-cinder-muted">
                  {p.evidence[0]}
                </pre>
              )}
            </button>
          ))}
        </div>

        <div className="rounded-lg border border-cinder-border bg-cinder-bg p-4">
          <div className="mb-1.5 text-[11px] uppercase tracking-wider text-cinder-muted">
            Incident overview
          </div>
          <p className="text-sm leading-relaxed text-cinder-text">{incident.overview}</p>
        </div>

        <div className="mt-4 rounded-lg border border-cinder-border bg-cinder-bg p-4">
          <div className="mb-1.5 text-[11px] uppercase tracking-wider text-cinder-muted">
            Verdict (engine)
          </div>
          <p className="text-sm leading-relaxed text-cinder-text">{incident.verdict}</p>
        </div>

        <div className="mt-4 flex flex-col gap-2">
          <div className="text-[11px] uppercase tracking-wider text-cinder-muted">
            Recommended actions
          </div>
          <ul className="flex flex-col gap-2">
            {incident.recommended_actions.map((a, i) => (
              <li key={i} className="flex gap-2 text-sm text-cinder-text">
                <span className="text-emerald-400">✓</span>
                <span>{a}</span>
              </li>
            ))}
          </ul>
        </div>

        <p className="mt-5 text-[11px] text-cinder-muted">
          Correlation is a hypothesis, not proof. Click any phase to open that alert's
          investigation.
        </p>
      </div>
    </div>
  )
}