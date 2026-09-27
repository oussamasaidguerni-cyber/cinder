import { useEffect, useState } from 'react'
import { api } from '../api'
import type { AuditEntry, AuditTrailResponse } from '../types'
import { SeverityBadge } from './Badges'

interface Props {
  onClose: () => void
}

const SIG_TONE: Record<string, string> = {
  unsupported_success_claim: 'border-red-500/40',
  wrong_record: 'border-red-500/40',
  no_progress_search: 'border-orange-500/40',
  repeated_questions: 'border-yellow-500/40',
  incomplete_finished: 'border-yellow-500/40',
}

export function AuditorModal({ onClose }: Props) {
  const [trail, setTrail] = useState<AuditTrailResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loadingAi, setLoadingAi] = useState(false)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [showRaw, setShowRaw] = useState(false)
  const [entries, setEntries] = useState<AuditEntry[]>([])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const load = (ai = false) => {
    api
      .audit(ai)
      .then(setTrail)
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : 'Audit unavailable'),
      )
  }

  useEffect(() => {
    load()
    api
      .auditEntries()
      .then((r) => setEntries(r))
      .catch(() => setEntries([]))
  }, [])

  const askAi = async () => {
    setLoadingAi(true)
    try {
      await load(true)
    } finally {
      setLoadingAi(false)
    }
  }

  const toggle = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  if (error && !trail)
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
        <div className="flex max-w-md flex-col gap-3 rounded-xl border border-cinder-border bg-cinder-panel p-6 text-sm text-yellow-400">
          {error}
          <button
            onClick={onClose}
            className="self-start rounded border border-cinder-border px-3 py-1 text-xs text-cinder-muted hover:text-cinder-text"
          >
            Close
          </button>
        </div>
      </div>
    )

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="max-h-[92vh] w-full max-w-4xl overflow-y-auto rounded-xl border border-cinder-border bg-cinder-panel p-6"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="mb-1 flex items-center justify-between">
          <div className="text-lg font-semibold">The Auditor · Find the Hidden Failures</div>
          <button
            onClick={onClose}
            className="rounded border border-cinder-border px-2 py-0.5 text-xs text-cinder-muted hover:text-cinder-text"
          >
            Esc
          </button>
        </div>
        <p className="mb-4 text-xs text-cinder-muted">
          An agent can finish without a technical error and still fail the user. Every CINDER run
          is recorded; the Auditor flags unsupported claims, repeated questions, no-progress
          searches, wrong records and work presented as finished — with evidence, and honest
          about what it cannot see.
        </p>

        {/* Stat chips */}
        <div className="mb-4 flex flex-wrap gap-2 text-xs">
          <Stat label="runs audited" value={trail?.entry_count ?? 0} />
          <Stat label="findings" value={trail?.findings.length ?? 0} tone="text-red-400" />
          <Stat label="problem groups" value={trail?.groups.length ?? 0} tone="text-orange-400" />
          <Stat label="recoveries" value={trail?.recoveries.length ?? 0} tone="text-emerald-400" />
          <Stat label="ambiguous" value={trail?.ambiguous.length ?? 0} tone="text-yellow-400" />
          <span className="inline-flex items-center self-center text-[11px] text-cinder-muted">
            detection {trail?.runtime_ms ?? 0}ms · {trail?.cost_note.split('—')[0].trim()}
          </span>
        </div>

        {/* Method + optional AI toggle */}
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          <span className="text-[11px] text-cinder-muted">
            {trail?.method} · {trail?.ai_status}
          </span>
          <div className="flex gap-2">
            <button
              onClick={askAi}
              disabled={loadingAi}
              className="rounded border border-sky-500/40 bg-sky-500/10 px-3 py-1.5 text-xs font-semibold text-sky-400 transition hover:bg-sky-500/20 disabled:opacity-50"
            >
              {trail?.ai_insights.length ? 'Refresh AI take' : loadingAi ? 'Asking AI…' : 'Ask AI: fix this first'}
            </button>
            <button
              onClick={() => setShowRaw((v) => !v)}
              className="rounded border border-cinder-border px-3 py-1.5 text-xs font-medium text-cinder-text hover:border-cinder-text/60"
            >
              {showRaw ? 'Hide transcript' : 'Show transcript'}
            </button>
          </div>
        </div>

        {/* AI insights */}
        {trail?.ai_insights.length ? (
          <div className="mb-5 flex flex-col gap-3">
            <div className="text-[11px] uppercase tracking-wider text-cinder-muted">
              AI take — what to reproduce first
            </div>
            {trail.ai_insights.map((ins) => (
              <div
                key={ins.signature}
                className="rounded-lg border border-sky-500/30 bg-sky-500/5 p-4"
              >
                <div className="mb-1 text-xs font-semibold text-sky-400">{ins.label}</div>
                <p className="text-sm leading-relaxed text-cinder-text">{ins.insight}</p>
              </div>
            ))}
          </div>
        ) : null}

        {/* Ranked groups */}
        {trail?.groups.length ? (
          <div className="mb-5 flex flex-wrap items-center gap-2">
            <span className="text-[11px] uppercase tracking-wider text-cinder-muted">
              ranked (extent × frequency)
            </span>
            {trail.groups.map((g, i) => (
              <span
                key={g.signature}
                className="inline-flex items-center gap-1.5 rounded-full border border-cinder-border bg-cinder-bg px-3 py-1 text-[11px] text-cinder-muted"
              >
                <span className="font-semibold text-cinder-text">#{i + 1}</span>
                {g.label} · {g.count} runs
              </span>
            ))}
          </div>
        ) : null}

        {/* Findings list */}
        <div className="mb-5 flex flex-col gap-3">
          <div className="text-[11px] uppercase tracking-wider text-cinder-muted">
            Ranked issue list — click a finding for the supporting messages &amp; tool results
          </div>
          {trail?.findings.length ? (
            trail.findings.map((f) => {
              const open = expanded.has(f.id)
              return (
                <button
                  key={f.id}
                  onClick={() => toggle(f.id)}
                  className={`flex flex-col gap-1 rounded-lg border bg-cinder-bg p-4 text-left transition hover:border-cinder-text/50 ${
                    SIG_TONE[f.signature] ?? 'border-cinder-border'
                  }`}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold text-cinder-text">{f.label}</span>
                    <SeverityBadge severity={f.severity} />
                    <span className="font-mono text-[11px] text-cinder-muted">
                      conf {Math.round(f.confidence * 100)}%
                    </span>
                    <span className="ml-auto font-mono text-[11px] text-cinder-muted">
                      {f.session_id} · {f.entry_ids.length} run{f.entry_ids.length > 1 ? 's' : ''}
                    </span>
                  </div>
                  {open && (
                    <div className="mt-2 flex flex-col gap-2 border-t border-cinder-border pt-3">
                      <p className="text-xs leading-relaxed text-cinder-muted">{f.explanation}</p>
                      <div className="flex flex-col gap-2">
                        {f.evidence.map((ev, i) => (
                          <pre
                            key={i}
                            className="whitespace-pre-wrap rounded border border-cinder-border bg-cinder-panel p-3 font-mono text-[11px] leading-relaxed text-cinder-muted"
                          >
                            {ev}
                          </pre>
                        ))}
                      </div>
                    </div>
                  )}
                </button>
              )
            })
          ) : (
            <p className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4 text-sm text-emerald-400">
              No hidden failures detected in the audited runs.
            </p>
          )}
        </div>

        {/* Recoveries */}
        {trail?.recoveries.length ? (
          <div className="mb-5 flex flex-col gap-2">
            <div className="text-[11px] uppercase tracking-wider text-emerald-400">
              Recoveries — NOT counted as failures (legitimate retries)
            </div>
            {trail.recoveries.map((r, i) => (
              <div
                key={i}
                className="flex flex-col gap-1 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3"
              >
                <div className="text-xs font-medium text-emerald-400">
                  {r.session_id} · {r.label}
                </div>
                {r.evidence.map((ev, j) => (
                  <pre
                    key={j}
                    className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-cinder-muted"
                  >
                    {ev}
                  </pre>
                ))}
              </div>
            ))}
          </div>
        ) : null}

        {/* Ambiguous */}
        {trail?.ambiguous.length ? (
          <div className="mb-5 flex flex-col gap-2">
            <div className="text-[11px] uppercase tracking-wider text-yellow-400">
              Ambiguous — may be legitimate retries (kept for human review)
            </div>
            {trail.ambiguous.map((f) => (
              <div
                key={f.id}
                className="flex flex-col gap-1 rounded-lg border border-yellow-500/30 bg-yellow-500/5 p-3"
              >
                <div className="text-xs font-semibold text-yellow-400">
                  {f.label}
                  <span className="ml-2 font-mono text-[11px] font-normal">
                    conf {Math.round(f.confidence * 100)}% · {f.session_id}
                  </span>
                </div>
                <p className="text-xs leading-relaxed text-cinder-muted">{f.explanation}</p>
              </div>
            ))}
          </div>
        ) : null}

        {/* Raw transcript */}
        {showRaw ? (
          <div className="mb-5 flex flex-col gap-2">
            <div className="text-[11px] uppercase tracking-wider text-cinder-muted">
              Entire agent transcript (conversation + tool calls)
            </div>
            <div className="max-h-72 overflow-y-auto rounded-lg border border-cinder-border">
              <table className="w-full text-left text-[11px] text-cinder-muted">
                <thead className="sticky top-0 bg-cinder-panel">
                  <tr>
                    {['time', 'op', 'session', 'alert', 'mode', 'model', 'ms', 'sev', 'text'].map((h) => (
                      <th key={h} className="border-b border-cinder-border px-2 py-1.5 font-medium">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="bg-cinder-bg">
                  {entries.map((e) => (
                    <tr key={e.id} className="border-b border-cinder-border/60 align-top">
                      <td className="whitespace-nowrap px-2 py-1.5">
                        {new Date(e.created_at).toLocaleTimeString()}
                      </td>
                      <td className="px-2 py-1.5 font-mono">{e.op}</td>
                      <td className="px-2 py-1.5 font-mono">{e.session_id}</td>
                      <td className="px-2 py-1.5 font-mono">{e.alert_id ?? '—'}</td>
                      <td className="px-2 py-1.5">{e.analysis_mode}</td>
                      <td className="max-w-[140px] truncate px-2 py-1.5 font-mono">
                        {e.model_used ?? '—'}
                      </td>
                      <td className="px-2 py-1.5">{e.latency_ms}</td>
                      <td className="px-2 py-1.5">{e.severity ?? '—'}</td>
                      <td className="max-w-xs truncate px-2 py-1.5">
                        {e.answer ?? e.summary ?? e.overview ?? '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : null}

        {/* Honesty panel */}
        <div className="rounded-lg border border-cinder-border bg-cinder-bg p-4">
          <div className="mb-1.5 text-[11px] uppercase tracking-wider text-cinder-muted">
            Honesty panel · limits, runtime, cost
          </div>
          <p className="mb-2 text-[11px] text-cinder-muted">{trail?.cost_note}</p>
          <ul className="list-inside list-disc text-[11px] leading-relaxed text-cinder-muted">
            {trail?.limitations.map((l, i) => (
              <li key={i}>{l}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}

function Stat({ label, value, tone = 'text-cinder-text' }: { label: string; value: number; tone?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded border border-cinder-border bg-cinder-bg px-3 py-1.5">
      <span className={`font-mono text-sm font-semibold ${tone}`}>{value}</span>
      <span className="text-cinder-muted">{label}</span>
    </span>
  )
}