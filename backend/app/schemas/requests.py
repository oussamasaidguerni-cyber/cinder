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


class BatchAnalysisItem(BaseModel):
    alert_id: str
    result: AnalysisResult