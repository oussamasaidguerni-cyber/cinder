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
from ..schemas.audit import AuditEntry
from ..schemas.correlation import CorrelatedIncident
from ..schemas.requests import (
    AskRequest,
    AskResponse,
    BatchAnalysisItem,
    IngestRequest,
    RawLogRequest,
    StatusUpdateRequest,
)
from ..services.analyzer import (
    analyze_alert_cached,
    analyze_raw_log,
    ask_question,
)
from ..services.audit import record_run
from ..services.correlation import correlate_chain
from ..services.simulator import simulate_alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _get_store() -> AlertStore:
    return AlertStore("data/cinder.db")


def _audit(
    session_id: str,
    op: str,
    *,
    alert_id: str | None = None,
    question: str | None = None,
    mode: str = "deterministic",
    model: str | None = None,
    latency_ms: int = 0,
    severity: str | None = None,
    confidence: int | None = None,
    threat_type: str | None = None,
    summary: str | None = None,
    answer: str | None = None,
    overview: str | None = None,
    actions_count: int | None = None,
    report_len: int | None = None,
    raw_log: str | None = None,
) -> None:
    """Append one agent run to the audit trail (record, don't raise)."""
    try:
        import time as _time
        from datetime import datetime, timezone

        record_run(
            AuditEntry(
                id=f"live-{int(_time.time() * 1000)}-{session_id}-{op}",
                session_id=session_id,
                op=op,
                alert_id=alert_id,
                question=question,
                analysis_mode=mode,
                model_used=model,
                latency_ms=latency_ms,
                severity=severity,
                confidence=confidence,
                threat_type=threat_type,
                summary=(summary or "")[:800] or None,
                answer=(answer or "")[:800] or None,
                overview=(overview or "")[:800] or None,
                actions_count=actions_count,
                report_len=report_len,
                raw_log=(raw_log or "")[:500] or None,
                created_at=datetime.now(timezone.utc),
            )
        )
    except Exception:
        pass  # auditing must never break the demo flow


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
    import time as _time

    store = _get_store()
    try:
        try:
            _t0 = _time.perf_counter()
            incident = correlate_chain(store)
            latency = int((_time.perf_counter() - _t0) * 1000)
            _audit(
                session_id=f"sess-live-corr-{incident.incident_id}",
                op="correlate",
                mode=incident.analysis_mode,
                model=incident.model_used,
                latency_ms=latency,
                severity="HIGH",
                confidence=incident.confidence,
                overview=incident.overview,
                actions_count=len(incident.recommended_actions),
                raw_log=incident.verdict[:500],
            )
            return incident
        except LookupError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    finally:
        store.close()


@router.post("/{alert_id}/analyze", response_model=AnalysisResult)
def analyze_alert_route(alert_id: str) -> AnalysisResult:
    """Analyze an alert: deterministic verdict + optional AI narrative."""
    import time as _time

    store = _get_store()
    try:
        alert = store.get_alert(alert_id)
    finally:
        store.close()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    _t0 = _time.perf_counter()
    result = analyze_alert_cached(alert)
    latency = int((_time.perf_counter() - _t0) * 1000)
    _audit(
        session_id=f"sess-live-ana-{alert_id}",
        op="analyze",
        alert_id=alert_id,
        mode=result.analysis_mode,
        model=result.model_used,
        latency_ms=latency,
        severity=result.severity,
        confidence=result.confidence,
        threat_type=result.threat_type,
        summary=result.summary,
        actions_count=len(result.recommended_actions),
        report_len=len(result.incident_report),
        raw_log=alert.raw_log,
    )
    return result


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
    import time as _time

    store = _get_store()
    try:
        alert = store.get_alert(alert_id)
    finally:
        store.close()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    _t0 = _time.perf_counter()
    answer, mode, model = ask_question(alert, req.question)
    latency = int((_time.perf_counter() - _t0) * 1000)
    _audit(
        session_id=f"sess-live-ask-{alert_id}",
        op="ask",
        alert_id=alert_id,
        question=req.question,
        mode=mode,
        model=model,
        latency_ms=latency,
        severity=alert.severity.value,
        answer=answer,
        raw_log=alert.raw_log,
    )
    return AskResponse(
        question=req.question,
        answer=answer,
        analysis_mode=mode,
        model_used=model,
    )


@router.post("/analyze-raw", response_model=AnalysisResult)
def analyze_raw_route(req: RawLogRequest) -> AnalysisResult:
    """Triage freeform log text pasted by the analyst."""
    import time as _time

    _t0 = _time.perf_counter()
    result = analyze_raw_log(req.text)
    latency = int((_time.perf_counter() - _t0) * 1000)
    _audit(
        session_id="sess-live-triage",
        op="triage",
        mode=result.analysis_mode,
        model=result.model_used,
        latency_ms=latency,
        severity=result.severity,
        confidence=result.confidence,
        threat_type=result.threat_type,
        summary=result.summary,
        actions_count=len(result.recommended_actions),
        report_len=len(result.incident_report),
        raw_log=req.text,
    )
    return result


@router.post("/simulate", response_model=Alert)
def simulate() -> Alert:
    """Inject a fresh fabricated alert for live demos."""
    store = _get_store()
    try:
        alert = simulate_alert(store)
        _audit(
            session_id=f"sess-live-sim-{alert.id}",
            op="simulate",
            alert_id=alert.id,
            mode="deterministic",
            severity=alert.severity.value,
            threat_type=alert.alert_type.value,
            raw_log=alert.raw_log,
        )
        return alert
    finally:
        store.close()


@router.post("/ingest", response_model=Alert)
def ingest(req: IngestRequest) -> Alert:
    """Real signals in: persist an alert from an actual log event.

    Accepts a sender-supplied classification or auto-detects from the text.
    Unrecognized patterns are rejected (422) rather than mis-labeled.
    """
    from ..services.ingestion import ingest_raw_log

    store = _get_store()
    try:
        try:
            alert, _type_source = ingest_raw_log(
                store,
                raw_log=req.raw_log,
                source=req.source,
                source_ip=req.source_ip,
                destination=req.destination,
                alert_type=req.alert_type,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        _audit(
            session_id=f"sess-live-ing-{alert.id}",
            op="ingest",
            alert_id=alert.id,
            mode="deterministic",
            severity=alert.severity.value,
            confidence=None,
            threat_type=alert.alert_type.value,
            summary="Real event ingested via /alerts/ingest.",
            raw_log=alert.raw_log,
        )
        return alert
    finally:
        store.close()