export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type AlertStatus = 'NEW' | 'INVESTIGATING' | 'CONFIRMED' | 'CLOSED'

export interface AlertSummary {
  id: string
  timestamp: string
  source: string
  source_ip: string
  destination: string
  alert_type: string
  severity: Severity
  status: AlertStatus
}

export interface Alert extends AlertSummary {
  raw_log: string
  description: string
}

export interface Stats {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
  by_type: Record<string, number>
}

export interface MitreAttack {
  technique_id: string
  technique_name: string
  tactic: string
}

export interface AnalysisResult {
  severity: Severity
  threat_type: string
  summary: string
  confidence: number
  evidence: string[]
  mitre_attack: MitreAttack | null
  recommended_actions: string[]
  false_positive_indicators: string[]
  incident_report: string
  analysis_mode: 'deterministic' | 'ai' | 'fallback'
  model_used: string | null
}

export interface Health {
  status: string
  version: string
  ai_provider: string
  ai_configured: boolean
}

export interface AskResponse {
  question: string
  answer: string
  analysis_mode: string
  model_used: string | null
}

export interface BatchAnalysisItem {
  alert_id: string
  result: AnalysisResult
}

export interface CorrelationPhase {
  order: number
  phase_name: string
  tactic: string
  technique_id: string
  technique_name: string
  alert_id: string
  severity: Severity
  confidence: number
  timestamp: string
  evidence: string[]
}

export interface CorrelatedIncident {
  incident_id: string
  title: string
  confidence: number
  phases: CorrelationPhase[]
  verdict: string
  overview: string
  recommended_actions: string[]
  analysis_mode: 'deterministic' | 'ai' | 'fallback'
  model_used: string | null
}

export interface AuditEntry {
  id: string
  session_id: string
  op: string
  alert_id: string | null
  question: string | null
  analysis_mode: string
  model_used: string | null
  latency_ms: number
  severity: Severity | null
  confidence: number | null
  threat_type: string | null
  summary: string | null
  answer: string | null
  overview: string | null
  actions_count: number | null
  report_len: number | null
  raw_log: string | null
  created_at: string
}

export interface AuditFinding {
  id: string
  signature: string
  label: string
  severity: Severity
  confidence: number
  session_id: string
  entry_ids: string[]
  evidence: string[]
  explanation: string
}

export interface AuditRecovery {
  session_id: string
  label: string
  entry_ids: string[]
  evidence: string[]
}

export interface AuditGroup {
  signature: string
  label: string
  severity: Severity
  count: number
  sessions: string[]
  score: number
}

export interface AuditInsight {
  signature: string
  label: string
  insight: string
}

export interface AuditTrailResponse {
  generated_at: string
  method: string
  ai_provider: string
  ai_status: string
  entry_count: number
  findings: AuditFinding[]
  groups: AuditGroup[]
  recoveries: AuditRecovery[]
  ambiguous: AuditFinding[]
  ai_insights: AuditInsight[]
  limitations: string[]
  runtime_ms: number
  cost_note: string
}

// --- Intel (real vulnerability intelligence) -------------------------------

export interface AttckTechnique {
  technique_id: string
  technique_name: string
  tactic: string
  description: string
  technique_url: string
  basis: string
}

export interface CvssMetric {
  version: string
  vector_string: string
  base_score: number
  base_severity: string
  attack_vector?: string | null
  attack_complexity?: string | null
  privileges_required?: string | null
  user_interaction?: string | null
  scope?: string | null
  exploitability_score?: number | null
  impact_score?: number | null
}

export interface AffectedProduct {
  cpe: string
  vendor?: string | null
  product?: string | null
}

export interface KevEntry {
  in_catalog: boolean
  catalog_status: string
  catalog_date?: string | null
  cve_id?: string | null
  vendor_project?: string | null
  product?: string | null
  vulnerability_name?: string | null
  date_added?: string | null
  short_description?: string | null
  required_action?: string | null
  due_date?: string | null
  known_ransomware_use?: boolean
}

export interface IntelReference {
  url: string
  tags: string[]
}

export interface IntelVerdict {
  priority: string
  priority_score: number
  known_exploited: boolean
  reasons: string[]
  formula: string
  thresholds: Record<string, number>
}

export interface IntelReport {
  mode: string
  model_used?: string | null
  explanation: string
  why_it_matters: string
  investigation: string[]
  remediation: string[]
  uncertainty: string
}

export interface IntelMetrics {
  data_kind: string
  cached_note?: string | null
  sources_consulted: string[]
  enrichment_ms: number
  ai_ms: number
  total_ms: number
}

export interface InventoryMatch {
  configured: boolean
  match_status: 'NO_INVENTORY' | 'IN_INVENTORY' | 'NOT_IN_INVENTORY'
  matched_cpes: string[]
  matched_products: string[]
}

export interface IntelFinding {
  cve_id: string
  data_kind: string
  retrieved_at: string
  source: string
  published?: string | null
  last_modified?: string | null
  vuln_status?: string | null
  description: string
  cvss?: CvssMetric | null
  cwes: string[]
  affected_products: AffectedProduct[]
  references: IntelReference[]
  kev: KevEntry
  attck: AttckTechnique[]
  inventory?: InventoryMatch | null
  verdict: IntelVerdict | null
  report: IntelReport | null
  metrics: IntelMetrics
  sources: string[]
}

export interface IntelSearchResult {
  cve_id: string
  published?: string | null
  base_score?: number | null
  base_severity?: string | null
  description: string
  cwes: string[]
  kev_status: string
  priority?: string | null
  data_kind: string
}

export interface IntelSourceInfo {
  name: string
  kind: string
  url: string
  note: string
  catalog_date?: string | null
}

export interface IntelSourcesResponse {
  sources: IntelSourceInfo[]
  cache: {
    cve_count: number
    kev_catalog_date?: string | null
    kev_last_fetched?: string | null
  }
}

export interface IntelStatsResponse {
  processed: number
  priority_distribution: Record<string, number>
  known_exploited: number
  newest_retrieved?: string | null
  kev_catalog_date?: string | null
}