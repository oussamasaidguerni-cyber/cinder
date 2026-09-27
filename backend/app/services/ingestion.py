"""Real alert ingestion: arbitrary raw logs from actual systems -> alerts.

This is the production "signals in" path. Unlike the simulator (fabricated
RFC-5737 fixtures labeled SYNTHETIC), ingested events are treated as real
evidence: they enter the same store, get a deterministic verdict from the same
engine, and go straight into the analyst queue.

When no explicit `alert_type` is supplied and the pattern is unrecognized,
ingestion refuses (422) instead of guessing a classification — fabricating a
label for unknown real traffic would be worse than rejecting it.
"""

from datetime import datetime, timezone

from ..data.store import AlertStore
from ..schemas.alerts import Alert, AlertStatus, AlertType, Severity
from ..services.engine import detect_type

_UTC = timezone.utc

_SEVERITY_BY_TYPE: dict[AlertType, Severity] = {
    AlertType.SSH_BRUTE_FORCE: Severity.HIGH,
    AlertType.POWERSHELL_ACTIVITY: Severity.MEDIUM,
    AlertType.WEB_ATTACK: Severity.HIGH,
    AlertType.PHISHING: Severity.MEDIUM,
    AlertType.OUTBOUND_CONNECTION: Severity.LOW,
}

_KNOWN_TYPES = {t.value for t in AlertType}


def ingest_raw_log(
    store: AlertStore,
    *,
    raw_log: str,
    source: str = "user-ingest",
    source_ip: str = "0.0.0.0",
    destination: str = "",
    alert_type: str | None = None,
) -> tuple[Alert, str]:
    """Create one alert from a real ingested log line.

    Returns (alert, classification_source) where classification_source is
    "explicit" (supplied by the sender) or "detected" (CINDER auto-detected).
    Raises ValueError when the pattern is unrecognized and no type was given.
    """
    if alert_type and alert_type in _KNOWN_TYPES:
        parsed_type = AlertType(alert_type)
        type_source = "explicit"
    else:
        detected = detect_type(raw_log)
        if detected is None:
            raise ValueError(
                "Unrecognized log pattern. Pass an explicit alert_type from the "
                "sender, or enable a parser for this source. CINDER won't guess "
                "a classification for unknown real traffic."
            )
        parsed_type = AlertType(detected)
        type_source = "detected"

    severity = _SEVERITY_BY_TYPE[parsed_type]
    alert = store.create_alert(
        Alert(
            id=store.next_id(),
            timestamp=datetime.now(_UTC),
            source=source,
            source_ip=source_ip,
            destination=destination or "-",
            alert_type=parsed_type,
            severity=severity,
            status=AlertStatus.NEW,
            raw_log=raw_log,
            description=(
                f"Ingested real event ({type_source} classification, {parsed_type.value}). "
                "Not synthetic — analyzed by the deterministic engine like every alert."
            ),
        )
    )
    return alert, type_source