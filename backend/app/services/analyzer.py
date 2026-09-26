"""Analysis pipeline: deterministic verdict, then optional AI narrative.

If the AI is configured and succeeds, we enrich narrative fields and mark the
result analysis_mode="ai". If the AI fails for any reason we keep the
deterministic result and mark analysis_mode="fallback" so demo viewers are
never misled into thinking a live AI call happened when it did not.
"""

import re
import time
from datetime import datetime, timezone

from ..ai.provider import AIError, get_provider
from ..schemas.alerts import Alert, AlertStatus, AlertType, Severity
from ..schemas.analysis import AnalysisResult
from .engine import analyze_deterministic, detect_type

_RAW_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Simple in-memory cache for batch analysis. Keyed by alert id; results are
# immutable once computed, so we only cache successes (AI or fallback both are
# final answers). Never store the raw alert text here.
_ANALYSIS_CACHE: dict[str, AnalysisResult] = {}


def build_raw_alert(text: str, alert_id: str) -> Alert:
    src_ip = "0.0.0.0"
    m = _RAW_IP_RE.search(text)
    if m:
        src_ip = m.group(0)
    detected = detect_type(text)
    return Alert(
        id=alert_id,
        timestamp=datetime.now(timezone.utc),
        source="manual paste",
        source_ip=src_ip,
        destination="—",
        alert_type=AlertType(detected) if detected else AlertType.OTHER,
        severity=Severity.LOW,
        status=AlertStatus.NEW,
        raw_log=text,
        description="Manually submitted log for triage.",
    )


def analyze_alert(alert: Alert) -> AnalysisResult:
    result = analyze_deterministic(alert)
    provider = get_provider()

    if provider.name == "gemini":
        try:
            enrichment = provider.enrich(alert, result)
            result = result.model_copy(
                update={
                    "summary": enrichment.summary,
                    "recommended_actions": enrichment.recommended_actions,
                    "false_positive_indicators": enrichment.false_positive_indicators,
                    "incident_report": enrichment.incident_report,
                    "analysis_mode": "ai",
                    "model_used": provider.model_name,
                }
            )
        except AIError:
            result = result.model_copy(
                update={"analysis_mode": "fallback", "model_used": provider.model_name}
            )
    else:
        # No API key: purely deterministic, honestly labeled as fallback/demo.
        result = result.model_copy(
            update={"analysis_mode": "fallback", "model_used": "deterministic"}
        )

    return result


def analyze_alert_cached(alert: Alert) -> AnalysisResult:
    """analyze_alert with an in-memory cache to keep the dashboard snappy."""
    if alert.id in _ANALYSIS_CACHE:
        return _ANALYSIS_CACHE[alert.id]
    result = analyze_alert(alert)
    _ANALYSIS_CACHE[alert.id] = result
    return result


def analyze_raw_log(text: str) -> AnalysisResult:
    """Triage arbitrary raw log text: detect type, deterministic engine, AI."""
    raw = build_raw_alert(text, alert_id=f"RAW-{int(time.time() * 1000) % 100000}")
    return analyze_alert(raw)


def ask_question(alert: Alert, question: str) -> tuple[str, str, str]:
    """Ask CINDER a scoped follow-up question about an alert.

    Returns (answer, analysis_mode, model_name).
    """
    result = analyze_alert_cached(alert)
    provider = get_provider()
    if provider.name != "gemini":
        return provider.answer(alert, result, question), "fallback", "deterministic"
    try:
        answer = provider.answer(alert, result, question)
        return answer, "ai", provider.model_name
    except AIError:
        first_action = (
            result.recommended_actions[0] if result.recommended_actions else "review the alert."
        )
        return (
            "Live AI is temporarily unavailable. Based on the deterministic verdict "
            f"({result.threat_type}, {result.severity} severity), the primary "
            f"recommended action is: {first_action}",
            "fallback",
            provider.model_name,
        )