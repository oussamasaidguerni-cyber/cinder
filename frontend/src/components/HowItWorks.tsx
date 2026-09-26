import { useEffect } from 'react'

interface Props {
  onClose: () => void
}

const STEPS = [
  {
    label: '1 · Ingest',
    title: 'Signals in',
    body: 'Alerts from SIEM, EDR, firewall and web logs — or any raw log you paste into the triage box.',
  },
  {
    label: '2 · Deterministic engine',
    title: 'The verdict is authoritative',
    body: 'Signature matching sets severity, threat type, confidence, evidence and MITRE ATT&CK mapping. No AI guesswork in the verdict.',
  },
  {
    label: '3 · Gemini enrichment',
    title: 'AI narrates, never decides',
    body: 'CINDER sends the verdict to Gemini to write the narrative summary, recommended actions, false-positive indicators and an incident report.',
  },
]

const PRINCIPLES = [
  ['Analysis modes', 'Every result shows how it was produced: live AI (Gemini), deterministic engine, or honest fallback.'],
  ['No fake alerts', 'Demo data uses RFC 5737 TEST-NET IPs that can never belong to real infrastructure.'],
  ['Explainable', 'Evidence lines and MITRE mappings are derived from the log itself, not hallucinated.'],
]

export function HowItWorks({ onClose }: Props) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-cinder-border bg-cinder-panel p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-1 flex items-center justify-between">
          <div className="text-lg font-semibold">How CINDER works</div>
          <button
            onClick={onClose}
            className="rounded border border-cinder-border px-2 py-0.5 text-xs text-cinder-muted hover:text-cinder-text"
          >
            Esc
          </button>
        </div>

        <div className="mb-5 flex flex-col gap-4">
          {STEPS.map((s, i) => (
            <div key={s.label} className="flex gap-4 rounded-lg border border-cinder-border bg-cinder-bg p-4">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-red-500/15 font-mono text-sm font-bold text-red-400">
                {i + 1}
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wider text-cinder-muted">{s.label}</div>
                <div className="text-sm font-semibold text-cinder-text">{s.title}</div>
                <p className="mt-1 text-sm leading-relaxed text-cinder-muted">{s.body}</p>
              </div>
            </div>
          ))}
        </div>

        <div className="rounded-lg border border-cinder-border p-4">
          <div className="mb-3 text-[11px] uppercase tracking-wider text-cinder-muted">Design principles</div>
          <div className="flex flex-col gap-3">
            {PRINCIPLES.map(([k, v]) => (
              <div key={k} className="flex gap-3 text-sm">
                <span className="shrink-0 font-semibold text-cinder-text">{k}</span>
                <span className="text-cinder-muted">{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}