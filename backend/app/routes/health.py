import os

from fastapi import APIRouter

from ..schemas import HealthResponse

router = APIRouter(tags=["health"])


def read_version() -> str:
    try:
        import importlib.metadata

        return importlib.metadata.version("cinder-backend")
    except Exception:
        return "0.1.0"


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    return HealthResponse(
        status="ok",
        version=read_version(),
        ai_provider="gemini" if key else "fallback",
        ai_configured=bool(key),
    )