from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class CorrelationPhase(BaseModel):
    order: int
    phase_name: str
    tactic: str
    technique_id: str
    technique_name: str
    alert_id: str
    severity: str
    confidence: int
    timestamp: datetime
    evidence: list[str] = Field(default_factory=list)


class CorrelatedIncident(BaseModel):
    """Multi-alert kill-chain hypothesis built by the correlation engine.

    The verdict and phases are ENGINE-GENERATED; the AI may only enrich the
    narrative `overview`. Never invents techniques not present in the phases.
    """

    incident_id: str
    title: str
    confidence: int = Field(ge=0, le=100)
    phases: list[CorrelationPhase]
    verdict: str
    overview: str
    recommended_actions: list[str] = Field(default_factory=list)
    analysis_mode: str = Field(
        default="deterministic", description="deterministic | ai | fallback"
    )
    model_used: Optional[str] = None