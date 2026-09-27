import { useEffect, useState } from 'react'
import { api } from './api'
import type { AnalysisResult, CorrelatedIncident, Health, Stats } from './types'
import { AlertTable } from './components/AlertTable'
import { AuditorModal } from './components/AuditorModal'
import { KpiCards, SeverityDistribution, StatusDistribution } from './components/Cards'
import { CorrelationModal } from './components/CorrelationModal'
import { HowItWorks } from './components/HowItWorks'
import { IntelModal } from './components/IntelModal'
import { Investigation } from './components/Investigation'
import { Logo } from './components/Logo'
import { TriageModal } from './components/TriageModal'

const AI_PROVIDER_LABEL: Record<string, string> = {
  nvidia: 'NVIDIA NIM',
  gemini: 'Gemini',
  fallback: 'deterministic engine',
}

export default function App() {
  const [openId, setOpenId] = useState<string | null>(
    () => window.location.hash.replace(/^#/, '') || null,
  )
  const [stats, setStats] = useState<Stats | null>(null)
  const [health, setHealth] = useState<Health | null>(null)
  const [refreshKey, setRefreshKey] = useState(0)
  const [triageOpen, setTriageOpen] = useState(false)
  const [howOpen, setHowOpen] = useState(false)
  const [lastTriage, setLastTriage] = useState<AnalysisResult | null>(null)
  const [simulating, setSimulating] = useState(false)
  const [simError, setSimError] = useState<string | null>(null)
  const [corrOpen, setCorrOpen] = useState(false)
  const [correlating, setCorrelating] = useState(false)
  const [incident, setIncident] = useState<CorrelatedIncident | null>(null)
  const [corrError, setCorrError] = useState<string | null>(null)
  const [auditorOpen, setAuditorOpen] = useState(false)
  const [intelOpen, setIntelOpen] = useState(false)

  const open = (id: string) => {
    window.location.hash = id
    setOpenId(id)
  }
  const close = () => {
    window.location.hash = ''
    setOpenId(null)
  }
  useEffect(() => {
    const onHash = () => setOpenId(window.location.hash.replace(/^#/, '') || null)
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const refresh = () => setRefreshKey((k) => k + 1)

  useEffect(() => {
    api
      .stats()
      .then(setStats)
      .catch(() => setStats(null))
    api
      .health()
      .then(setHealth)
      .catch(() => setHealth(null))
  }, [refreshKey])

  useEffect(() => {
    const timer = window.setInterval(() => {
      api
        .stats()
        .then(setStats)
        .catch(() => setStats(null))
      api
        .health()
        .then(setHealth)
        .catch(() => setHealth(null))
    }, 15000)
    return () => window.clearInterval(timer)
  }, [])

  const simulate = async () => {
    setSimulating(true)
    setSimError(null)
    try {
      const a = await api.simulate()
      setOpenId(a.id)
      window.location.hash = a.id
      refresh()
    } catch (e: unknown) {
      setSimError(e instanceof Error ? e.message : 'Simulation failed')
    } finally {
      setSimulating(false)
    }
  }

  const openCorrelation = async () => {
    setCorrOpen(true)
    setCorrelating(true)
    setCorrError(null)
    try {
      const inc = await api.correlate()
      setIncident(inc)
    } catch (e: unknown) {
      setCorrError(
        e instanceof Error
          ? 'Correlation unavailable — ' + e.message
          : 'Correlation failed',
      )
      setIncident(null)
    } finally {
      setCorrelating(false)
    }
  }

  const openFromIncident = (alertId: string) => {
    setCorrOpen(false)
    open(alertId)
  }

  const aiProviderLabel = health?.ai_provider
    ? (AI_PROVIDER_LABEL[health.ai_provider] ?? health.ai_provider)
    : 'deterministic engine'

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-10 border-b border-cinder-border bg-cinder-bg/95 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-x-4 gap-y-2 py-3 px-4 sm:py-4">
          <div className="flex items-center gap-3">
            <Logo size={32} />
            <div>
              <div className="text-sm font-semibold tracking-wide">CINDER</div>
              <div className="text-[11px] text-cinder-muted hidden sm:block">
                AI-Powered SOC Analyst Copilot
              </div>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs text-cinder-muted sm:gap-4">
            <button
              onClick={() => setHowOpen(true)}
              className="rounded border border-cinder-border px-3 py-1.5 text-xs font-medium text-cinder-text hover:border-cinder-text/60"
            >
              How it works
            </button>
            <button
              onClick={simulate}
              disabled={simulating}
              className="rounded border border-cinder-border px-3 py-1.5 text-xs font-medium text-cinder-text hover:border-emerald-400/50 hover:text-emerald-400 disabled:opacity-50"
            >
              {simulating ? 'Simulating…' : 'Simulate alert'}
            </button>
            <button
              onClick={() => setTriageOpen(true)}
              className="rounded border border-cinder-border px-3 py-1.5 text-xs font-medium text-cinder-text hover:border-red-400/40 hover:text-red-400"
            >
              Triage log
            </button>
            <button
              onClick={() => setAuditorOpen(true)}
              className="rounded border border-cinder-border px-3 py-1.5 text-xs font-medium text-cinder-text hover:border-sky-400/50 hover:text-sky-400"
            >
              Auditor
            </button>
            <button
              onClick={() => setIntelOpen(true)}
              className="rounded border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-400 hover:border-emerald-400/70 hover:bg-emerald-500/20"
            >
              Threat intel
            </button>
            <span className="hidden md:inline">v{health?.version ?? '0.1.0'}</span>
            <span className="inline-flex items-center gap-1.5">
              <span
                className={
                  health?.ai_configured
                    ? 'h-2 w-2 rounded-full bg-emerald-400'
                    : 'h-2 w-2 rounded-full bg-yellow-400'
                }
              />
              {health?.ai_configured ? 'AI connected' : 'Fallback mode'}
            </span>
          </div>
        </div>
      </header>

      {(triageOpen || howOpen || corrOpen || auditorOpen || intelOpen) && (
        <>
          {intelOpen && <IntelModal onClose={() => setIntelOpen(false)} />}
          {auditorOpen && <AuditorModal onClose={() => setAuditorOpen(false)} />}
          {triageOpen && (
            <TriageModal
              onClose={() => setTriageOpen(false)}
              onResult={(r) => setLastTriage(r)}
              onIngested={refresh}
            />
          )}
          {howOpen && <HowItWorks onClose={() => setHowOpen(false)} providerLabel={aiProviderLabel} />}
          {corrOpen &&
            (incident ? (
              <CorrelationModal
                incident={incident}
                key={incident.incident_id}
                onClose={() => setCorrOpen(false)}
                onOpenAlert={openFromIncident}
              />
            ) : correlating ? (
              <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
                <div className="rounded-xl border border-cinder-border bg-cinder-panel p-6 text-sm text-cinder-muted">
                  Correlating alerts…
                </div>
              </div>
            ) : (
              <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
                <div className="flex max-w-md flex-col gap-3 rounded-xl border border-cinder-border bg-cinder-panel p-6 text-sm text-yellow-400">
                  {corrError ?? 'Correlation unavailable.'}
                  <button
                    onClick={() => setCorrOpen(false)}
                    className="self-start rounded border border-cinder-border px-3 py-1 text-xs text-cinder-muted hover:text-cinder-text"
                  >
                    Close
                  </button>
                </div>
              </div>
            ))}
        </>
      )}

      <main className="mx-auto max-w-6xl px-4 py-6">
        {openId ? (
          <Investigation
            alertId={openId}
            onBack={close}
            onStatusChange={refresh}
          />
        ) : (
          <div className="flex flex-col gap-4">
            <KpiCards stats={stats} />
            {lastTriage && (
              <div className="rounded-lg border border-cinder-border bg-cinder-panel p-3 text-sm">
                <span className="text-[11px] uppercase tracking-wider text-cinder-muted">
                  Last triaged log: </span>
                <span className="font-semibold text-cinder-text">{lastTriage.threat_type}</span>
                <span className="mx-2 text-cinder-muted">·</span>
                <span
                  className={
                    lastTriage.severity === 'CRITICAL' || lastTriage.severity === 'HIGH'
                      ? 'text-red-400'
                      : lastTriage.severity === 'MEDIUM'
                        ? 'text-yellow-400'
                        : 'text-sky-400'
                  }
                >
                  {lastTriage.severity}
                </span>
                <span className="mx-2 text-cinder-muted">·</span>
                <span
                  className={
                    lastTriage.analysis_mode === 'ai' ? 'text-emerald-400' : 'text-yellow-400'
                  }
                >
                  {lastTriage.analysis_mode === 'ai' ? 'live AI' : 'fallback'}
                </span>
              </div>
            )}
            <div className="grid gap-4 lg:grid-cols-3">
              <div className="lg:col-span-2">
                <AlertTable onOpen={open} refreshKey={refreshKey} />
              </div>
              <div className="flex flex-col gap-4">
                <SeverityDistribution stats={stats} />
                <StatusDistribution stats={stats} />
                <div className="rounded-lg border border-cinder-border bg-cinder-panel p-4">
                  <div className="mb-1 text-[11px] uppercase tracking-wider text-cinder-muted">
                    Correlated campaign
                  </div>
                  <p className="text-sm text-cinder-muted">
                    Three alerts may be one intrusion: Initial Access → Execution →
                    Command &amp; Control.
                  </p>
                  <button
                    onClick={openCorrelation}
                    disabled={correlating}
                    className="mt-3 w-full rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs font-semibold text-red-400 transition hover:bg-red-500/20 disabled:opacity-50"
                  >
                    {correlating ? 'Correlating…' : 'View attack chain'}
                  </button>
                  {corrError && (
                    <div className="mt-2 text-[11px] text-yellow-400">{corrError}</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
        {simError && (
          <div className="mt-4 text-center text-xs text-red-400">{simError}</div>
        )}
      </main>

      <footer className="border-t border-cinder-border py-5">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-2 px-4 text-[11px] text-cinder-muted">
          <span>Built for GOMYCODE × NVIDIA Hackathon 2026 · FastAPI + React · so-called security</span>
          <span className="inline-flex items-center gap-1.5">
            {health?.ai_configured
              ? `Deterministic engine + ${aiProviderLabel}`
              : 'Deterministic engine only'}
            · threat intel from NVD/KEV/ATT&CK · demo alerts labeled SYNTHETIC
          </span>
        </div>
      </footer>
    </div>
  )
}