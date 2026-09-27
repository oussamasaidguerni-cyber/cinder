"""The Auditor: schemas for the agent-run audit trail and its findings.

CINDER records every agent operation (analyze / ask / correlate / triage /
simulate) as an AuditEntry — the equivalent of an "agent conversation with
tool calls". The Auditor then scans the trail for hidden failures, groups
related cases into sessions, and presents a ranked, evidence-backed issue list.

This directly addresses the SupplyzPro "Find the Hidden Failures" challenge:
flagging unsupported success claims, repeated questions, no-progress searches,
wrong customer records and incomplete work presented as finished — while
separating real failures from legitimate retries.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class AuditEntry(BaseModel):
    """One agent run. Immutable, append-only, written the moment the op returns."""

    id: str
    session_id: str = Field(description="e.g. sess-ana-001; groups related agent calls")
    op: str = Field(description="analyze | ask | correlate | triage | simulate")
    alert_id: str | None = None
    question: str | None = None
    analysis_mode: str = Field(
        default="deterministic", description="deterministic | ai | fallback"
    )
    model_used: str | None = None
    latency_ms: int = 0
    severity: str | None = None
    confidence: int | None = None
    threat_type: str | None = None
    summary: str | None = Field(
        default=None, description="narrative artifact from analyze/enrich"
    )
    answer: str | None = Field(default=None, description="artifact from ask")
    overview: str | None = Field(default=None, description="artifact from correlate")
    actions_count: int | None = None
    report_len: int | None = None
    raw_log: str | None = Field(
        default=None, description="grounding text the run was built from (truncated)"
    )
    created_at: datetime


class AuditFinding(BaseModel):
    """A single hidden-failure finding with the evidence that supports it."""

    id: str
    signature: str = Field(
        description=(
            "unsupported_success_claim | repeated_questions | no_progress_search "
            "| wrong_record | incomplete_finished"
        )
    )
    label: str
    severity: str
    confidence: float = Field(ge=0, le=1)
    session_id: str
    entry_ids: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list, description="quoted messages / tool results")
    explanation: str


class AuditRecovery(BaseModel):
    """A run that hit a problem but recovered honestly — NOT counted as a failure."""

    session_id: str
    label: str
    entry_ids: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class AuditGroup(BaseModel):
    """Related failures collapsed into one ranked problem (cluster)."""

    signature: str
    label: str
    severity: str
    count: int
    sessions: list[str] = Field(default_factory=list)
    score: float = Field(description="severity weight x frequency x confidence")


class AuditInsight(BaseModel):
    """Optional LLM-narrated 'fix what first' paragraph for a top group."""

    signature: str
    label: str
    insight: str


CHALLENGE_LABELS: dict[str, str] = {
    "unsupported_success_claim": "Unsupported success claim",
    "repeated_questions": "Repeated questions",
    "no_progress_search": "No-progress search",
    "wrong_record": "Wrong customer record",
    "incomplete_finished": "Incomplete presented as finished",
}

SEVERITY_WEIGHT: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class AuditTrailResponse(BaseModel):
    """Full Auditor output: ranked findings, grouped sessions, honesty panel."""

    generated_at: datetime
    method: str = "deterministic checks"
    ai_provider: str = "fallback"
    ai_status: str = "deterministic only — no external calls"
    entry_count: int
    findings: list[AuditFinding] = Field(default_factory=list)
    groups: list[AuditGroup] = Field(default_factory=list)
    recoveries: list[AuditRecovery] = Field(default_factory=list)
    ambiguous: list[AuditFinding] = Field(default_factory=list)
    ai_insights: list[AuditInsight] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    runtime_ms: int = 0
    cost_note: str = "$0.00 — deterministic detection only"