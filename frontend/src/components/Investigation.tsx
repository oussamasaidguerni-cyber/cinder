import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import type { Alert, AlertStatus, AnalysisResult, AskResponse } from '../types'
import { SeverityBadge, StatusBadge, TypeChip } from './Badges'

interface Props {
  alertId: string
  onBack: () => void
  onStatusChange: () => void
}

const MODE_LABEL: Record<AnalysisResult['analysis_mode'], string> = {
  ai: 'Live AI analysis',
  deterministic: 'Deterministic engine',
  fallback: 'Fallback — network/API unavailable',
}

const STATUSES: AlertStatus[] = ['NEW', 'INVESTIGATING', 'CONFIRMED', 'CLOSED']

const SUGGESTED_QUESTIONS = [
  'Why is this confidence level warranted?',
  'What logs should I pull next to confirm this?',
  'Could this be a false positive?',
  'Draft a short report for management.',
]

function ConfidenceRing({ value }: { value: number }) {
  const color = value >= 85 ? 'text-red-400' : value >= 70 ? 'text-orange-400' : 'text-yellow-400'
  return (
    <div className="flex items-center gap-3">
      <div className={`font-mono text-3xl font-semibold ${color}`}>{value}%</div>
      <div className="text-[11px] uppercase tracking-wider text-cinder-muted">Confidence</div>
    </div>
  )
}

interface QaEntry {
  q: string
  a: string
  mode: string
  model: string | null
}

function AskCinder({ alertId, alert }: { alertId: string; alert: Alert }) {
  const [question, setQuestion] = useState('')
  const [entries, setEntries] = useState<QaEntry[]>([])
  const [asking, setAsking] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const ask = useCallback(
    async (q: string) => {
      if (!q.trim() || asking) return
      setAsking(true)
      setError(null)
      try {
        const res: AskResponse = await api.ask(alertId, q.trim())
        setEntries((prev) => [...prev, { q: res.question, a: res.answer, mode: res.analysis_mode, model: res.model_used }])
        setQuestion('')
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : 'Ask failed')
      } finally {
        setAsking(false)
      }
    },
    [alertId, asking],
  )

  return (
    <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
      <div className="mb-2 text-[11px] uppercase tracking-wider text-cinder-muted">
        Ask CINDER about this alert
      </div>

      {entries.length === 0 && (
        <div className="mb-2 flex flex-wrap gap-2">
          {SUGGESTED_QUESTIONS.map((q) => (
            <button
              key={q}
              onClick={() => ask(q)}
              disabled={asking}
              className="rounded border border-cinder-border bg-cinder-bg px-2.5 py-1 text-xs text-cinder-muted hover:text-cinder-text disabled:opacity-50"
            >
              {q}
            </button>
          ))}
        </div>
      )}

      <div className="flex flex-col gap-3">
        {entries.map((e, i) => (
          <div key={i} className="flex flex-col gap-1.5">
            <div className="text-sm font-medium text-cinder-text">Q: {e.q}</div>
            <div className="rounded bg-cinder-bg p-3 text-sm leading-relaxed text-cinder-text">
              {e.a}
            </div>
            <div
              className={`text-[10px] ${
                e.mode === 'ai' ? 'text-emerald-400' : 'text-yellow-400'
              }`}
            >
              {e.mode === 'ai' ? `Live AI (${e.model ?? 'gemini'})` : 'Fallback response'}
            </div>
          </div>
        ))}
      </div>

      <div className="mt-3 flex gap-2">
        <input
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') ask(question)
          }}
          placeholder={`Ask about ${alert.source_ip}…`}
          className="flex-1 rounded border border-cinder-border bg-cinder-bg px-3 py-1.5 text-sm text-cinder-text placeholder:text-cinder-muted"
        />
        <button
          onClick={() => ask(question)}
          disabled={asking || !question.trim()}
          className="rounded bg-cinder-text px-3 py-1.5 text-sm font-semibold text-cinder-bg hover:opacity-90 disabled:opacity-50"
        >
          {asking ? 'Asking…' : 'Ask'}
        </button>
      </div>
      {error && <div className="mt-2 text-xs text-red-400">{error}</div>}
    </div>
  )
}

export function Investigation({ alertId, onBack, onStatusChange }: Props) {
  const [alert, setAlert] = useState<Alert | null>(null)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [updatingStatus, setUpdatingStatus] = useState(false)
  const [copied, setCopied] = useState(false)

  const exportCase = async () => {
    if (!alert || !result) return
    const mitre = result.mitre_attack
      ? `| Technique | ${result.mitre_attack.technique_id} — ${result.mitre_attack.technique_name} (${result.mitre_attack.tactic}) |\n`
      : ''
    const mode = `${
      result.analysis_mode === 'ai'
        ? 'Live AI'
        : result.analysis_mode === 'fallback'
          ? 'Fallback / no API'
          : 'Deterministic engine'
    }${result.model_used ? ` — ${result.model_used}` : ''}`
    const md = `# CINDER Case Report — ${alert.id}

**Threat type:** ${result.threat_type}
**Severity:** ${result.severity} · **Confidence:** ${result.confidence}%
**Analysis mode:** ${mode}
**Timestamp:** ${new Date(alert.timestamp).toISOString()}
**Source:** ${alert.source} · ${alert.source_ip} → ${alert.destination}
**Status:** ${alert.status}
${mitre}
## Summary
${result.summary}

## Evidence
${result.evidence.map((e) => `\`\`\`\n${e}\n\`\`\``).join('\n')}

## Recommended actions
${result.recommended_actions.map((a) => `- ${a}`).join('\n')}

## False-positive indicators
${result.false_positive_indicators.map((a) => `- ${a}`).join('\n')}

## Incident report
${result.incident_report}

---
Generated by CINDER — AI-Powered SOC Analyst Copilot (GOMYCODE × NVIDIA Hackathon 2026)
`
    await navigator.clipboard.writeText(md)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 2000)
  }

  useEffect(() => {
    let cancelled = false
    setAlert(null)
    setResult(null)
    setError(null)
    api
      .alert(alertId)
      .then((a) => {
        if (!cancelled) setAlert(a)
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Failed to load alert')
      })
    return () => {
      cancelled = true
    }
  }, [alertId])

  const analyze = useCallback(async () => {
    setAnalyzing(true)
    setError(null)
    try {
      const res = await api.analyze(alertId)
      setResult(res)
      onStatusChange()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Analysis failed')
    } finally {
      setAnalyzing(false)
    }
  }, [alertId, onStatusChange])

  const setStatus = useCallback(
    async (status: AlertStatus) => {
      if (!alert) return
      setUpdatingStatus(true)
      try {
        const updated = await api.updateStatus(alert.id, status)
        setAlert(updated)
        onStatusChange()
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : 'Status update failed')
      } finally {
        setUpdatingStatus(false)
      }
    },
    [alert, onStatusChange],
  )

  if (error && !alert) {
    return (
      <div className="mx-auto max-w-3xl p-8 text-center text-red-400">
        {error}
        <div className="mt-4">
          <button onClick={onBack} className="rounded border border-cinder-border px-3 py-1.5 text-sm">
            Back
          </button>
        </div>
      </div>
    )
  }

  if (!alert) {
    return <div className="max-w-3xl mx-auto p-8 text-center text-cinder-muted">Loading alert…</div>
  }

  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-4">
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="rounded border border-cinder-border px-3 py-1.5 text-sm text-cinder-muted hover:text-cinder-text"
        >
          ← Back to dashboard
        </button>
        <div className="flex items-center gap-2">
          <TypeChip type={alert.alert_type} />
          <SeverityBadge severity={alert.severity} />
          <StatusBadge status={alert.status} />
          {alert.description.includes('[SYNTHETIC]') && (
            <span className="inline-flex items-center rounded border border-yellow-500/30 bg-yellow-500/15 px-2 py-0.5 text-[11px] font-semibold text-yellow-400">
              SYNTHETIC demo alert
            </span>
          )}
        </div>
      </div>

      {alert.description.includes('[SYNTHETIC]') && (
        <div className="rounded border border-yellow-500/30 bg-yellow-500/10 px-4 py-2 text-xs text-yellow-300/90">
          This is fabricated demonstration data (RFC 5737 TEST-NET IPs) injected by the
          simulator. The deterministic engine analyzes it exactly like a real alert so the
          workflow is identical — but it is not real evidence.
        </div>
      )}

      <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <div className="text-[11px] uppercase tracking-wider text-cinder-muted">
            Investigation workflow
          </div>
          <StatusBadge status={alert.status} />
        </div>
        <div className="flex flex-wrap gap-2">
          {STATUSES.map((s) => (
            <button
              key={s}
              onClick={() => setStatus(s)}
              disabled={updatingStatus || alert.status === s}
              className={`rounded px-3 py-1.5 text-xs font-semibold border transition disabled:opacity-40 ${
                alert.status === s
                  ? 'border-cinder-text bg-cinder-text text-cinder-bg'
                  : 'border-cinder-border bg-cinder-bg text-cinder-muted hover:text-cinder-text'
              }`}
            >
              {alert.status === s ? '● ' : ''}
              {s}
            </button>
          ))}
        </div>
      </div>

      <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
          <div>
            <div className="text-[11px] uppercase tracking-wider text-cinder-muted">Alert ID</div>
            <div className="font-mono text-cinder-text">{alert.id}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-cinder-muted">Timestamp</div>
            <div>{new Date(alert.timestamp).toLocaleString()}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-cinder-muted">Source</div>
            <div>{alert.source}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-cinder-muted">Source IP</div>
            <div className="font-mono">{alert.source_ip}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-cinder-muted">Destination</div>
            <div className="font-mono text-cinder-muted">{alert.destination}</div>
          </div>
        </div>
        <p className="mt-3 text-sm text-cinder-muted">{alert.description}</p>
      </div>

      <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
        <div className="mb-2 text-[11px] uppercase tracking-wider text-cinder-muted">Raw evidence</div>
        <div className="max-h-48 overflow-y-auto rounded bg-cinder-bg p-3">
          <pre className="whitespace-pre-wrap font-mono text-xs leading-relaxed text-cinder-text">
            {alert.raw_log}
          </pre>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={analyze}
          disabled={analyzing}
          className="rounded-lg bg-cinder-text px-4 py-2 text-sm font-semibold text-cinder-bg hover:opacity-90 disabled:opacity-50"
        >
          {analyzing ? 'Analyzing…' : result ? 'Re-analyze with CINDER' : 'Analyze with CINDER'}
        </button>
        {result && (
          <span
            className={`text-xs ${
              result.analysis_mode === 'ai'
                ? 'text-emerald-400'
                : result.analysis_mode === 'fallback'
                  ? 'text-yellow-400'
                  : 'text-sky-400'
            }`}
          >
            {MODE_LABEL[result.analysis_mode]}
            {result.model_used ? ` · ${result.model_used}` : ''}
          </span>
        )}
      </div>

      {error && <div className="text-sm text-red-400">{error}</div>}

      {result && (
        <div className="flex flex-col gap-4">
          <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-lg font-semibold text-cinder-text">{result.threat_type}</div>
                <div className="mt-0.5 flex items-center gap-2">
                  <SeverityBadge severity={result.severity} />
                </div>
              </div>
              <ConfidenceRing value={result.confidence} />
            </div>
            <p className="mt-3 text-sm leading-relaxed text-cinder-text">{result.summary}</p>
          </div>

          {result.mitre_attack && (
            <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
              <div className="mb-2 text-[11px] uppercase tracking-wider text-cinder-muted">
                MITRE ATT&CK
              </div>
              <div className="flex flex-wrap items-center gap-3 text-sm">
                <span className="rounded border border-cinder-border bg-cinder-bg px-2 py-1 font-mono text-xs text-cinder-text">
                  {result.mitre_attack.technique_id}
                </span>
                <span className="text-cinder-text">{result.mitre_attack.technique_name}</span>
                <span className="text-cinder-muted">· {result.mitre_attack.tactic}</span>
              </div>
            </div>
          )}

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
              <div className="mb-2 text-[11px] uppercase tracking-wider text-cinder-muted">
                Recommended actions
              </div>
              <ul className="flex flex-col gap-2 text-sm text-cinder-text">
                {result.recommended_actions.map((a, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="text-emerald-400">✓</span>
                    <span>{a}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
              <div className="mb-2 text-[11px] uppercase tracking-wider text-cinder-muted">
                False-positive indicators
              </div>
              <ul className="flex flex-col gap-2 text-sm text-cinder-muted">
                {result.false_positive_indicators.map((a, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="text-yellow-400">?</span>
                    <span>{a}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
            <div className="mb-2 text-[11px] uppercase tracking-wider text-cinder-muted">Evidence</div>
            <div className="flex flex-col gap-2">
              {result.evidence.map((line, i) => (
                <pre
                  key={i}
                  className="whitespace-pre-wrap rounded bg-cinder-bg p-2 font-mono text-xs text-cinder-text"
                >
                  {line}
                </pre>
              ))}
            </div>
          </div>

          <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
            <div className="mb-2 flex items-center justify-between">
              <div className="text-[11px] uppercase tracking-wider text-cinder-muted">
                Incident report
              </div>
              <button
                onClick={exportCase}
                className="rounded border border-cinder-border px-3 py-1 text-xs text-cinder-muted hover:text-cinder-text"
              >
                {copied ? 'Copied ✓' : 'Export case (markdown)'}
              </button>
            </div>
            <p className="text-sm leading-relaxed text-cinder-text">{result.incident_report}</p>
            <button
              onClick={() => navigator.clipboard.writeText(result.incident_report)}
              className="mt-3 rounded border border-cinder-border px-3 py-1 text-xs text-cinder-muted hover:text-cinder-text"
            >
              Copy report
            </button>
          </div>
        </div>
      )}

      {result && <AskCinder alertId={alertId} alert={alert} />}
    </div>
  )
}