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