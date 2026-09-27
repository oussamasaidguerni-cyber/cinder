from fastapi import APIRouter

from ..ai.provider import get_provider
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
    provider = get_provider()
    return HealthResponse(
        status="ok",
        version=read_version(),
        ai_provider=provider.name,
        ai_configured=provider.is_live(),
    )