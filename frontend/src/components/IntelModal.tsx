import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import type {
  IntelFinding,
  IntelSearchResult,
  IntelSourcesResponse,
} from '../types'
import { DataKindBadge, KevStatusPill } from './Badges'

const EXAMPLES = [
  'CVE-2021-44228',
  'CVE-2023-44487',
  'CVE-2024-3400',
  'CVE-2024-6387',
]

const PRIORITY_STYLES: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
  INFORMATIONAL: 'bg-cinder-panel text-cinder-muted border-cinder-border',
}

function fmt(ts?: string | null): string {
  if (!ts) return '—'
  const d = new Date(ts)
  return isNaN(d.getTime()) ? String(ts) : d.toUTCString()
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-cinder-border bg-cinder-bg p-4">
      <div className="mb-2 text-[11px] uppercase tracking-wider text-cinder-muted">
        {title}
      </div>
      {children}
    </div>
  )
}

export function IntelModal({ onClose }: { onClose: () => void }) {
  const [query, setQuery] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<IntelSearchResult[] | null>(null)
  const [finding, setFinding] = useState<IntelFinding | null>(null)
  const [findingBusy, setFindingBusy] = useState(false)
  const [findingError, setFindingError] = useState<string | null>(null)
  const [sources, setSources] = useState<IntelSourcesResponse | null>(null)

  useEffect(() => {
    api
      .intelSources()
      .then(setSources)
      .catch(() => setSources(null))
  }, [])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const search = useCallback(async (term: string) => {
    if (!term.trim()) return
    setBusy(true)
    setError(null)
    setFinding(null)
    setResults(null)
    try {
      const res = await api.intelSearch(term.trim())
      if (res.length === 0) setError('No real CVE matched that query in NVD.')
      setResults(res)
    } catch (e: unknown) {
      setError(e instanceof Error ? `NVD search error: ${e.message}` : 'NVD search failed')
    } finally {
      setBusy(false)
    }
  }, [])

  const open = useCallback(
    async (cveId: string) => {
      setFindingBusy(true)
      setFindingError(null)
      try {
        const f = await api.intelAnalyze(cveId)
        setFinding(f)
        setResults(null)
      } catch (e: unknown) {
        setFindingError(
          e instanceof Error
            ? `Live source unavailable: ${e.message}`
            : 'Live source unavailable',
        )
      } finally {
        setFindingBusy(false)
      }
    },
    [],
  )

  const onSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    search(query)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="flex max-h-[92vh] w-full max-w-3xl flex-col overflow-hidden rounded-xl border border-cinder-border bg-cinder-panel"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-cinder-border p-4">
          <div>
            <div className="text-lg font-semibold">Threat intelligence</div>
            <div className="text-[11px] text-cinder-muted">
              Real records from NIST NVD · CISA KEV · MITRE ATT&CK — live vs cached labeled
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded border border-cinder-border px-2 py-0.5 text-xs text-cinder-muted hover:text-cinder-text"
          >
            Esc
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4">
          {!finding && (
            <>
              <form onSubmit={onSearchSubmit} className="flex gap-2">
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="CVE id (e.g. CVE-2021-44228) or keyword"
                  className="flex-1 rounded border border-cinder-border bg-cinder-bg px-3 py-2 text-sm text-cinder-text placeholder:text-cinder-muted focus:border-cinder-text/60 focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={busy}
                  className="rounded border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs font-semibold text-emerald-400 hover:bg-emerald-500/20 disabled:opacity-50"
                >
                  {busy ? 'Querying NVD…' : 'Look up'}
                </button>
              </form>

              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] text-cinder-muted">Try:</span>
                {EXAMPLES.map((c) => (
                  <button
                    key={c}
                    onClick={() => open(c)}
                    disabled={findingBusy}
                    className="rounded border border-cinder-border bg-cinder-bg px-2 py-0.5 font-mono text-[11px] text-sky-400 hover:border-sky-500/50"
                  >
                    {c}
                  </button>
                ))}
              </div>

              {error && (
                <div className="mt-3 rounded border border-yellow-500/30 bg-yellow-500/10 p-3 text-xs text-yellow-300">
                  {error}
                  <button
                    onClick={() => open('CVE-2021-44228')}
                    className="ml-2 underline hover:text-yellow-100"
                  >
                    Load example CVE-2021-44228
                  </button>
                </div>
              )}

              {results && results.length > 0 && (
                <div className="mt-4 flex flex-col gap-2">
                  <div className="text-[11px] uppercase tracking-wider text-cinder-muted">
                    {results.length} real NVD results — click for the full package
                  </div>
                  {results.map((r) => (
                    <button
                      key={r.cve_id}
                      onClick={() => open(r.cve_id)}
                      className="rounded-lg border border-cinder-border bg-cinder-bg p-3 text-left transition hover:border-sky-500/50"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-sm font-semibold text-cinder-text">
                          {r.cve_id}
                        </span>
                        {r.base_severity && (
                          <span
                            className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-semibold ${
                              PRIORITY_STYLES[r.base_severity] ?? PRIORITY_STYLES.LOW
                            }`}
                          >
                            {r.base_severity}
                          </span>
                        )}
                        <span className="text-[11px] text-cinder-muted">
                          CVSS {r.base_score ?? 'n/a'}
                        </span>
                        <KevStatusPill status={r.kev_status} />
                      </div>
                      <p className="mt-1 line-clamp-2 text-xs text-cinder-muted">
                        {r.description}
                      </p>
                      <div className="mt-1 flex flex-wrap gap-1 text-[10px] text-cinder-muted">
                        {r.cwes.map((c) => (
                          <span
                            key={c}
                            className="rounded bg-cinder-panel border border-cinder-border px-1.5 py-0.5"
                          >
                            {c}
                          </span>
                        ))}
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </>
          )}

          {findingBusy && (
            <div className="flex flex-col items-center justify-center gap-2 py-16 text-sm text-cinder-muted">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-cinder-border border-t-emerald-400" />
              Fetching verified intelligence…
            </div>
          )}

          {findingError && (
            <div className="rounded border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
              {findingError}
              <div className="mt-2 text-xs text-cinder-muted">
                CINDER never fabricates intelligence: when a live source is down
                and there is no cached record, it returns an explicit error instead.
              </div>
              <button
                onClick={() => open('CVE-2021-44228')}
                className="mt-3 rounded border border-cinder-border px-3 py-1 text-xs text-cinder-muted hover:text-cinder-text"
              >
                Back
              </button>
            </div>
          )}

          {finding && (
            <div className="flex flex-col gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-lg font-bold text-cinder-text">
                  {finding.cve_id}
                </span>
                <DataKindBadge kind={finding.data_kind} />
                {finding.verdict && (
                  <span
                    className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-bold ${
                      PRIORITY_STYLES[finding.verdict.priority] ?? PRIORITY_STYLES.LOW
                    }`}
                  >
                    PRIORITY {finding.verdict.priority} · {finding.verdict.priority_score}/100
                  </span>
                )}
                {finding.kev.in_catalog && <KevStatusPill status="IN_KEV" />}
              </div>

              {finding.metrics.cached_note && (
                <div className="rounded border border-sky-500/30 bg-sky-500/10 p-2 text-xs text-sky-300">
                  {finding.metrics.cached_note}
                </div>
              )}

              {finding.inventory && finding.inventory.match_status === 'IN_INVENTORY' && (
                <div className="rounded border border-red-500/40 bg-red-500/10 p-3">
                  <div className="text-[11px] font-bold uppercase tracking-wider text-red-300">
                    Affects our inventory — verify exposure now
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {finding.inventory.matched_products.map((p) => (
                      <span
                        key={p}
                        className="rounded bg-red-500/20 border border-red-500/30 px-2 py-0.5 font-mono text-[11px] text-red-200"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                  <p className="mt-1 text-xs text-cinder-muted">
                    Matched against the operator-configured inventory
                    (CINDER_INVENTORY). Vulnerability intelligence that matters to this
                    environment — still not evidence of compromise.
                  </p>
                </div>
              )}

              {finding.inventory && finding.inventory.match_status === 'NOT_IN_INVENTORY' && (
                <div className="rounded border border-cinder-border bg-cinder-bg p-3">
                  <div className="text-[11px] font-bold uppercase tracking-wider text-emerald-400">
                    Not in our inventory
                  </div>
                  <p className="mt-1 text-xs text-cinder-muted">
                    Inventory configured and this product is not present — no matching
                    vendor:product in CINDER_INVENTORY.
                  </p>
                </div>
              )}

              {finding.inventory && finding.inventory.match_status === 'NO_INVENTORY' && (
                <div className="rounded border border-cinder-border bg-cinder-bg p-3">
                  <div className="text-[11px] font-bold uppercase tracking-wider text-cinder-muted">
                    Irrelevant without context
                  </div>
                  <p className="mt-1 text-xs text-cinder-muted">
                    No inventory configured, so CINDER cannot say whether this affects
                    your environment. Set CINDER_INVENTORY (e.g.
                    paloaltonetworks:pan-os,apache:log4j) to get answers that matter to you.
                  </p>
                </div>
              )}

              {finding.kev.in_catalog && (
                <div className="rounded border border-red-500/40 bg-red-500/10 p-3">
                  <div className="text-[11px] font-bold uppercase tracking-wider text-red-300">
                    CISA Known Exploited — confirmed exploited in the wild
                  </div>
                  <div className="mt-1 text-xs text-cinder-muted">
                    {finding.kev.vulnerability_name ?? finding.cve_id} · added{' '}
                    {finding.kev.date_added ?? '—'} · due {finding.kev.due_date ?? '—'}
                  </div>
                  {finding.kev.short_description && (
                    <p className="mt-1 text-xs text-cinder-text">
                      {finding.kev.short_description}
                    </p>
                  )}
                  {finding.kev.required_action && (
                    <p className="mt-1 text-xs text-yellow-300">
                      Required action: {finding.kev.required_action}
                    </p>
                  )}
                </div>
              )}

              <Section title={`Vulnerability · published ${fmt(finding.published)}`}>
                <p className="text-sm leading-relaxed text-cinder-text">
                  {finding.description || 'No English description published by NVD.'}
                </p>
                {finding.vuln_status && (
                  <div className="mt-2 text-[11px] text-cinder-muted">
                    Status: {finding.vuln_status} · last modified {fmt(finding.last_modified)}
                  </div>
                )}
                {finding.cvss && (
                  <div className="mt-3 rounded border border-cinder-border bg-cinder-panel p-3">
                    <div className="text-[11px] uppercase tracking-wider text-cinder-muted">
                      CVSS {finding.cvss.version}
                    </div>
                    <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 font-mono text-xs text-cinder-text">
                      <span>Score {finding.cvss.base_score}</span>
                      <span>AV {finding.cvss.attack_vector ?? '?'}</span>
                      <span>PR {finding.cvss.privileges_required ?? '?'}</span>
                      <span>UI {finding.cvss.user_interaction ?? '?'}</span>
                      <span className="truncate">{finding.cvss.vector_string}</span>
                    </div>
                  </div>
                )}
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {finding.cwes.map((c) => (
                    <span
                      key={c}
                      className="rounded border border-cinder-border bg-cinder-panel px-2 py-0.5 font-mono text-[11px] text-cinder-muted"
                    >
                      {c}
                    </span>
                  ))}
                  {finding.cwes.length === 0 && (
                    <span className="text-[11px] text-cinder-muted">
                      No CWE classification published by NVD.
                    </span>
                  )}
                </div>
                {finding.affected_products.length > 0 && (
                  <div className="mt-3">
                    <div className="text-[11px] uppercase tracking-wider text-cinder-muted">
                      Affected products
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      {finding.affected_products.slice(0, 12).map((p) => (
                        <span
                          key={p.cpe}
                          className="rounded bg-cinder-panel border border-cinder-border px-2 py-0.5 font-mono text-[10px] text-cinder-muted"
                          title={p.cpe}
                        >
                          {p.vendor}:{p.product}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </Section>

              {finding.verdict && (
                <Section title="Why this verdict? — deterministic, no AI">
                  <ul className="flex flex-col gap-1.5">
                    {finding.verdict.reasons.map((r, i) => (
                      <li key={i} className="flex gap-2 text-xs text-cinder-muted">
                        <span className="text-emerald-400">✓</span>
                        <span>{r}</span>
                      </li>
                    ))}
                  </ul>
                  <div className="mt-3 rounded border border-cinder-border bg-cinder-panel p-2 font-mono text-[11px] text-cinder-muted">
                    {finding.verdict.formula}
                  </div>
                </Section>
              )}

              {finding.attck.length > 0 && (
                <Section title="MITRE ATT&CK association">
                  <div className="flex flex-col gap-3">
                    {finding.attck.map((t) => (
                      <div
                        key={t.technique_id}
                        className="rounded border border-cinder-border bg-cinder-panel p-3"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <a
                            href={t.technique_url}
                            target="_blank"
                            rel="noreferrer"
                            className="font-mono text-xs font-semibold text-sky-400 hover:underline"
                          >
                            {t.technique_id}
                          </a>
                          <span className="text-xs font-semibold text-cinder-text">
                            {t.technique_name}
                          </span>
                          <span className="rounded bg-cinder-panel border border-cinder-border px-1.5 py-0.5 text-[10px] text-cinder-muted">
                            {t.tactic}
                          </span>
                        </div>
                        <p className="mt-1 text-xs text-cinder-muted">{t.description}</p>
                        <p className="mt-1 text-[11px] italic text-yellow-300/80">
                          Association basis: {t.basis}
                        </p>
                        <p className="mt-1 text-[10px] text-cinder-muted">
                          Technique metadata © The MITRE Corporation · this is CINDER's
                          reasoned association from the CWE class, not a MITRE claim about
                          this CVE.
                        </p>
                      </div>
                    ))}
                  </div>
                </Section>
              )}

              {finding.report && (
                <Section
                  title={
                    finding.report.mode === 'ai'
                      ? `AI narration (evidence-only)${finding.report.model_used ? ` · ${finding.report.model_used}` : ''}`
                      : 'Report (deterministic fallback — AI unavailable)'
                  }
                >
                  <p className="text-sm leading-relaxed text-cinder-text">
                    {finding.report.explanation}
                  </p>
                  {finding.report.why_it_matters && (
                    <div className="mt-3">
                      <div className="text-[11px] font-semibold uppercase tracking-wider text-cinder-muted">
                        Why it matters
                      </div>
                      <p className="mt-1 text-xs text-cinder-muted">
                        {finding.report.why_it_matters}
                      </p>
                    </div>
                  )}
                  {finding.report.investigation.length > 0 && (
                    <div className="mt-3">
                      <div className="text-[11px] font-semibold uppercase tracking-wider text-cinder-muted">
                        Investigation steps
                      </div>
                      <ul className="mt-1 list-disc pl-4 text-xs text-cinder-muted">
                        {finding.report.investigation.map((s, i) => (
                          <li key={i}>{s}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {finding.report.remediation.length > 0 && (
                    <div className="mt-3">
                      <div className="text-[11px] font-semibold uppercase tracking-wider text-cinder-muted">
                        Remediation
                      </div>
                      <ul className="mt-1 list-disc pl-4 text-xs text-cinder-muted">
                        {finding.report.remediation.map((s, i) => (
                          <li key={i}>{s}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {finding.report.uncertainty && (
                    <p className="mt-3 text-[11px] italic text-yellow-300/80">
                      {finding.report.uncertainty}
                    </p>
                  )}
                  <p className="mt-3 text-[10px] text-cinder-muted">
                    AI narrates verified evidence only; the verdict was produced by the
                    deterministic engine. This is vulnerability intelligence, not evidence
                    of an intrusion in this environment.
                  </p>
                </Section>
              )}

              {finding.references.length > 0 && (
                <Section title="References">
                  <div className="flex flex-col gap-1.5">
                    {finding.references.slice(0, 8).map((r, i) => (
                      <a
                        key={i}
                        href={r.url}
                        target="_blank"
                        rel="noreferrer"
                        className="truncate font-mono text-[11px] text-sky-400 hover:underline"
                      >
                        {r.url}
                      </a>
                    ))}
                  </div>
                </Section>
              )}

              <Section title="Provenance">
                <div className="flex flex-col gap-1 font-mono text-[11px] text-cinder-muted">
                  <span>Retrieved: {fmt(finding.retrieved_at)} · {finding.data_kind}</span>
                  <span>Total: {finding.metrics.total_ms}ms (enrichment {finding.metrics.enrichment_ms}ms, AI {finding.metrics.ai_ms}ms)</span>
                  <span>Sources: {finding.metrics.sources_consulted.join(' · ')}</span>
                </div>
              </Section>

              <button
                onClick={() => {
                  setFinding(null)
                  setResults(null)
                }}
                className="self-start rounded border border-cinder-border px-3 py-1 text-xs text-cinder-muted hover:text-cinder-text"
              >
                ← Back to search
              </button>
            </div>
          )}
        </div>

        <div className="border-t border-cinder-border p-4">
          <div className="text-[11px] uppercase tracking-wider text-cinder-muted">
            Sources
          </div>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {(sources?.sources ?? []).map((s) => (
              <span
                key={s.name}
                className="inline-flex items-center gap-1 rounded border border-cinder-border bg-cinder-bg px-2 py-0.5 text-[10px] text-cinder-muted"
                title={s.note}
              >
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400/70" />
                {s.name}
              </span>
            ))}
            {sources && (
              <span className="ml-auto text-[10px] text-cinder-muted">
                {sources.cache.cve_count} processed · KEV catalog{' '}
                {sources.cache.kev_catalog_date ?? 'n/a'}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}