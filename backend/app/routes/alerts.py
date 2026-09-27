from fastapi import APIRouter, HTTPException, Query

from ..data.store import AlertStore
from ..schemas.alerts import (
    Alert,
    AlertStatus,
    AlertSummary,
    Severity,
    StatsResponse,
)
from ..schemas.analysis import AnalysisResult
from ..schemas.correlation import CorrelatedIncident
from ..schemas.requests import (
    AskRequest,
    AskResponse,
    BatchAnalysisItem,
    RawLogRequest,
    StatusUpdateRequest,
)
from ..services.analyzer import (
    analyze_alert_cached,
    analyze_raw_log,
    ask_question,
)
from ..services.correlation import correlate_chain
from ..services.simulator import simulate_alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _get_store() -> AlertStore:
    return AlertStore("data/cinder.db")


@router.get("", response_model=list[AlertSummary])
def list_alerts(
    severity: Severity | None = Query(default=None),
    status: AlertStatus | None = Query(default=None),
) -> list[AlertSummary]:
    store = _get_store()
    try:
        return store.list_alerts(severity=severity, status=status)
    finally:
        store.close()


@router.get("/stats", response_model=StatsResponse)
def alerts_stats() -> StatsResponse:
    store = _get_store()
    try:
        return StatsResponse(**store.stats())
    finally:
        store.close()


@router.get("/analyze-all", response_model=list[BatchAnalysisItem])
def analyze_all() -> list[BatchAnalysisItem]:
    """Analyze every alert (with cache) so the dashboard shows AI chips."""
    store = _get_store()
    try:
        alerts = [store.get_alert(a.id) for a in store.list_alerts()]
    finally:
        store.close()
    items: list[BatchAnalysisItem] = []
    for a in alerts:
        if a is None:
            continue
        items.append(BatchAnalysisItem(alert_id=a.id, result=analyze_alert_cached(a)))
    return items


@router.get("/{alert_id}", response_model=Alert)
def get_alert(alert_id: str) -> Alert:
    store = _get_store()
    try:
        alert = store.get_alert(alert_id)
    finally:
        store.close()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/correlate", response_model=CorrelatedIncident)
def correlate_alerts() -> CorrelatedIncident:
    """Build a multi-alert kill-chain incident from related alerts present."""
    store = _get_store()
    try:
        try:
            return correlate_chain(store)
        except LookupError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    finally:
        store.close()


@router.post("/{alert_id}/analyze", response_model=AnalysisResult)
def analyze_alert_route(alert_id: str) -> AnalysisResult:
    """Analyze an alert: deterministic verdict + optional AI narrative."""
    store = _get_store()
    try:
        alert = store.get_alert(alert_id)
    finally:
        store.close()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return analyze_alert_cached(alert)


@router.patch("/{alert_id}/status", response_model=Alert)
def update_alert_status(alert_id: str, req: StatusUpdateRequest) -> Alert:
    store = _get_store()
    try:
        alert = store.update_status(alert_id, req.status)
    finally:
        store.close()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/{alert_id}/ask", response_model=AskResponse)
def ask_about_alert(alert_id: str, req: AskRequest) -> AskResponse:
    store = _get_store()
    try:
        alert = store.get_alert(alert_id)
    finally:
        store.close()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    answer, mode, model = ask_question(alert, req.question)
    return AskResponse(
        question=req.question,
        answer=answer,
        analysis_mode=mode,
        model_used=model,
    )


@router.post("/analyze-raw", response_model=AnalysisResult)
def analyze_raw_route(req: RawLogRequest) -> AnalysisResult:
    """Triage freeform log text pasted by the analyst."""
    return analyze_raw_log(req.text)


@router.post("/simulate", response_model=Alert)
def simulate() -> Alert:
    """Inject a fresh fabricated alert for live demos."""
    store = _get_store()
    try:
        return simulate_alert(store)
    finally:
        store.close()