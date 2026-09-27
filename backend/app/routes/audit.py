"""The Auditor endpoints: inspect the agent-run trail and its hidden failures."""

from fastapi import APIRouter, Query

from ..schemas.audit import AuditEntry, AuditTrailResponse
from ..services.audit import build_trail
from ..data.store import AlertStore

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=AuditTrailResponse)
def audit_trail(ai_pass: bool = Query(default=False, alias="ai")) -> AuditTrailResponse:
    """Ranked hidden-failure findings, grouped sessions, and the honesty panel.

    Deterministic by default (fast, free). Pass `?ai=1` to add a narrated
    "fix this first" take for the top groups from the configured provider.
    """
    return build_trail(ai_pass=ai_pass)


@router.get("/entries", response_model=list[AuditEntry])
def audit_entries() -> list[AuditEntry]:
    """Raw agent transcript: every recorded operation, oldest first."""
    store = AlertStore("data/cinder.db")
    try:
        return store.list_audit()
    finally:
        store.close()