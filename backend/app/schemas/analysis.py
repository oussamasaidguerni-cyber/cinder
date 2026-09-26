from pydantic import BaseModel, Field


class AnalysisResult(BaseModel):
    """Validated structured output of the analysis pipeline.

    Produced primarily by the deterministic engine; the AI layer may enrich
    the narrative fields (summary, recommended_actions, false_positive_indicators,
    incident_report) but never the security verdict itself.
    """

    severity: str = Field(description="LOW | MEDIUM | HIGH | CRITICAL")
    threat_type: str
    summary: str
    confidence: int = Field(ge=0, le=100)
    evidence: list[str] = []
    mitre_attack: dict | None = Field(
        default=None, description="{technique_id, technique_name, tactic} or null"
    )
    recommended_actions: list[str] = []
    false_positive_indicators: list[str] = []
    incident_report: str = ""
    analysis_mode: str = Field(
        default="deterministic", description="deterministic | ai | fallback"
    )
    model_used: str | None = None