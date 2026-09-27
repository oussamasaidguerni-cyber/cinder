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