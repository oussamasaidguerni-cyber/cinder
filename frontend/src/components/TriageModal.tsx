import { useEffect, useState } from 'react'
import { api } from '../api'
import type { AnalysisResult, Severity } from '../types'
import { SeverityBadge } from './Badges'

interface Props {
  onClose: () => void
  onResult: (r: AnalysisResult) => void
  onIngested: () => void
}

const SAMPLES: Record<string, string> = {
  SSH: 'Mar 10 23:14:15 srv-web sshd[32010]: Failed password for invalid user admin from 203.0.113.45 port 59224 ssh2\nMar 10 23:14:17 srv-web sshd[32014]: Failed password for user root from 203.0.113.45 port 59231 ssh2',
  SQLi: '198.51.100.99 - - [10/Mar/2024:23:18:02 +0000] "GET /product?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 400 182 "-" "Mozilla/5.0"',
  Webshell: 'Jan 2 03:14:11 web nginx: 198.51.100.7 - POST /upload.php - "cmd=whoami" 200\nJan 2 03:14:12 web nginx: 198.51.100.7 - GET /shell.php?id=cat%20/etc/passwd 200',
}

function modeTone(m: AnalysisResult['analysis_mode']) {
  return m === 'ai' ? 'text-emerald-400' : m === 'fallback' ? 'text-yellow-400' : 'text-sky-400'
}

export function TriageModal({ onClose, onResult, onIngested }: Props) {
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [savedId, setSavedId] = useState<string | null>(null)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const run = async (payload: string) => {
    if (!payload.trim() || busy) return
    setBusy(true)
    setError(null)
    try {
      const r = await api.analyzeRaw(payload)
      setResult(r)
      onResult(r)
} catch (e: unknown) {
      setError(e instanceof Error ? 'Triage failed' : 'Triage failed')
    } finally {
      setBusy(false)
    }
  }

  const save = async () => {
    if (!text.trim() || saving) return
    setSaving(true)
    setError(null)
    try {
      const a = await api.ingest({ raw_log: text, source: 'analyst-paste' })
      setSavedId(a.id)
      onIngested()
    } catch (e: unknown) {
      setError(
        e instanceof Error
          ? `Ingest rejected: ${e.message}. CINDER won't classify unknown patterns — analyze it or pass a type.`
          : 'Ingest failed',
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="flex max-h-[90vh] w-full max-w-2xl flex-col overflow-y-auto rounded-xl border border-cinder-border bg-cinder-panel p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center justify-between">
          <div className="text-sm font-semibold">Triage a raw log</div>
          <button onClick={onClose} className="rounded border border-cinder-border px-2 py-0.5 text-xs text-cinder-muted hover:text-cinder-text">
            Esc
          </button>
        </div>
        <p className="mb-3 text-xs text-cinder-muted">
          Paste any server / firewall / auth log. CINDER detects the type, runs the deterministic
          engine, and lets AI refine the verdict.
        </p>

        <div className="mb-2 flex flex-wrap gap-2">
          {Object.entries(SAMPLES).map(([label, sample]) => (
            <button
              key={label}
              onClick={() => setText(sample)}
              className="rounded border border-cinder-border bg-cinder-bg px-2.5 py-1 text-xs text-cinder-muted hover:text-cinder-text"
            >
              {label} sample
            </button>
          ))}
        </div>

        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={'sshd[123]: Failed password for invalid user root from 203.0.113.5 port 51422 ssh2\n# or any WAF/firewall/nginx line you have around'}
          className="h-40 w-full resize-y rounded-lg border border-cinder-border bg-cinder-bg p-3 font-mono text-xs leading-relaxed text-cinder-text placeholder:text-cinder-muted"
        />

        <div className="mt-3 flex items-center gap-3">
          <button
            onClick={() => run(text)}
            disabled={busy || !text.trim()}
            className="rounded-lg bg-cinder-text px-4 py-2 text-sm font-semibold text-cinder-bg hover:opacity-90 disabled:opacity-50"
          >
            {busy ? 'Analyzing…' : 'Analyze'}
          </button>
          <button
            onClick={save}
            disabled={saving || !text.trim()}
            className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-400 hover:bg-emerald-500/20 disabled:opacity-50"
          >
            {saving ? 'Saving…' : 'Save as real alert'}
          </button>
          {savedId && (
            <span className="text-xs text-emerald-400">
              ingested as <span className="font-mono">{savedId}</span> — it's now in the queue
            </span>
          )}
          {error && <span className="text-xs text-red-400">{error}</span>}
        </div>

        {result && (
          <div className="mt-4 flex flex-col gap-3">
            <div className={`text-[10px] uppercase tracking-wider ${modeTone(result.analysis_mode)}`}>
              {result.analysis_mode === 'ai'
                ? `Live AI · ${result.model_used ?? 'gemini'}`
                : result.analysis_mode === 'fallback'
                  ? 'Fallback / deterministic mode'
                  : 'Deterministic engine'}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={result.severity as Severity} />
              <span className="text-sm font-semibold text-cinder-text">{result.threat_type}</span>
              <span className="ml-auto font-mono text-xs text-cinder-muted">
                confidence {result.confidence}%
              </span>
            </div>
            <p className="text-sm leading-relaxed text-cinder-text">{result.summary}</p>
            {result.mitre_attack && (
              <div className="text-xs text-cinder-muted">
                MITRE: <span className="font-mono text-cinder-text">{result.mitre_attack.technique_id}</span> {result.mitre_attack.technique_name}
              </div>
            )}
            <div className="flex flex-col gap-1.5">
              {result.evidence.slice(0, 3).map((line, i) => (
                <pre key={i} className="whitespace-pre-wrap rounded bg-cinder-bg p-2 font-mono text-[11px] text-cinder-text">
                  {line}
                </pre>
              ))}
            </div>
            <button
              onClick={() => navigator.clipboard.writeText(result.incident_report)}
              className="self-start rounded border border-cinder-border px-3 py-1 text-xs text-cinder-muted hover:text-cinder-text"
            >
              Copy incident report
            </button>
          </div>
        )}
      </div>
    </div>
  )
}