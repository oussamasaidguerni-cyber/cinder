from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    version: str
    ai_provider: str
    ai_configured: bool