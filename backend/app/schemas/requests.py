from pydantic import BaseModel, Field

from .alerts import AlertStatus
from .analysis import AnalysisResult


class StatusUpdateRequest(BaseModel):
    status: AlertStatus


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=500)


class AskResponse(BaseModel):
    question: str
    answer: str
    analysis_mode: str = "ai"
    model_used: str | None = None


class RawLogRequest(BaseModel):
    text: str = Field(min_length=1, max_length=50_000)


class IngestRequest(BaseModel):
    raw_log: str = Field(min_length=1, max_length=50_000)
    source: str = Field(default="user-ingest", max_length=200)
    source_ip: str = Field(default="0.0.0.0", max_length=64)
    destination: str = Field(default="", max_length=256)
    alert_type: str | None = Field(
        default=None,
        description=(
            "Optional explicit classification from the sending system. When "
            "absent CINDER auto-detects from the log text."
        ),
    )


class BatchAnalysisItem(BaseModel):
    alert_id: str
    result: AnalysisResult