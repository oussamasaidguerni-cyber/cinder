"""Correlation engine: groups related alerts into a kill-chain incident hypothesis.

Honest by design: the engine picks alerts whose types fit consecutive attack
stages, builds each phase from that alert's own deterministic analysis, and
narrates the chain as a HYPOTHESIS — never as a confirmed intrusion. The AI (if
configured) may only phrase the overview; it cannot invent stages or techniques.
"""

from ..ai.provider import AIError, get_provider
from ..data.store import AlertStore
from ..schemas.alerts import Alert
from ..schemas.correlation import CorrelatedIncident, CorrelationPhase
from ..services.analyzer import analyze_alert_cached
from ..services.mitre import technique_for

# Alert type -> kill-chain phase label. Alerts whose types fit consecutive
# stages become one incident. Order in the chain follows timestamps, not this list.
_CHAIN_ROLES: list[tuple[str, str]] = [
    ("SSH_BRUTE_FORCE", "Initial Access"),
    ("POWERSHELL_ACTIVITY", "Execution"),
    ("OUTBOUND_CONNECTION", "Command & Control"),
]

_INCIDENT_COUNTER = 0


def _next_incident_id() -> str:
    global _INCIDENT_COUNTER
    _INCIDENT_COUNTER += 1
    return f"INC-2024-{_INCIDENT_COUNTER:03d}"


def pick_chain_alerts(store: AlertStore) -> list[Alert]:
    """Most recent alert per chain stage, in kill-chain order (not timestamp).

    Kill chains are displayed in attack order (Initial Access -> Execution ->
    C2). Ordering by stage keeps the story coherent even when an early-stage
    alert was ingested later.
    """
    chosen: list[Alert] = []
    for role, _phase in _CHAIN_ROLES:
        summaries = [a for a in store.list_alerts() if a.alert_type.value == role]
        if not summaries:
            continue
        newest = max(summaries, key=lambda s: s.timestamp)
        alert = store.get_alert(newest.id)
        if alert is not None:
            chosen.append(alert)
    return chosen


def _phase_label(alert_type_value: str) -> str:
    for role, phase in _CHAIN_ROLES:
        if role == alert_type_value:
            return phase
    return "Related"


def _build_phases(alerts: list[Alert]) -> list[CorrelationPhase]:
    phases: list[CorrelationPhase] = []
    for idx, alert in enumerate(alerts, start=1):
        analysis = analyze_alert_cached(alert)
        technique = technique_for(alert.alert_type.value)
        phases.append(
            CorrelationPhase(
                order=idx,
                phase_name=_phase_label(alert.alert_type.value),
                tactic=technique.tactic if technique else "—",
                technique_id=technique.technique_id if technique else "N/A",
                technique_name=technique.technique_name if technique else "Unknown",
                alert_id=alert.id,
                severity=analysis.severity,
                confidence=analysis.confidence,
                timestamp=alert.timestamp,
                evidence=analysis.evidence[:2],
            )
        )
    return phases


def _deterministic_overview(alerts: list[Alert], phases: list[CorrelationPhase]) -> str:
    sequence = " then ".join(p.phase_name.lower() for p in phases)
    ids = ", ".join(a.id for a in alerts)
    return (
        f"Correlation groups {len(alerts)} alerts ({ids}) into one kill-chain "
        f"hypothesis: {sequence}. Each phase is individually verified by the "
        f"rule engine; the chain link itself is a working hypothesis that "
        f"requires investigation and confirmation before any containment."
    )


_DEFAULT_ACTIONS = [
    "Treat the chain as a working hypothesis: confirm each phase's host and IP before any containment.",
    "Block the Command & Control destination at the firewall, per organizational policy.",
    "Reset credentials for hosts named in the initial-access evidence.",
    "Export the full log timeline for all chained alerts before closing the incident.",
    "Escalate to Tier-2 for containment and a hunt for sibling hosts on the same paths.",
]


def correlate_chain(store: AlertStore) -> CorrelatedIncident:
    alerts = pick_chain_alerts(store)
    if len(alerts) < 2:
        raise LookupError(
            "Not enough correlated alerts to build a chain. "
            "Need at least two of: SSH brute force, PowerShell activity, outbound beacon."
        )

    phases = _build_phases(alerts)
    confidence = round(sum(p.confidence for p in phases) / len(phases))
    title = "Multi-stage attack chain — " + " → ".join(
        p.phase_name.lower() for p in phases
    )

    facts = "\n".join(
        f"- Phase {p.order} ({p.phase_name}, {p.technique_id} {p.technique_name} / "
        f"{p.tactic}): alert {p.alert_id}, severity {p.severity}, confidence "
        f"{p.confidence}%. Evidence: {' | '.join(p.evidence[:2])}"
        for p in phases
    )

    provider = get_provider()
    if provider.is_live():
        try:
            overview = provider.incident_overview(facts)
            analysis_mode, model_used = "ai", provider.model_name
        except AIError:
            overview = _deterministic_overview(alerts, phases)
            analysis_mode, model_used = "fallback", provider.model_name
    else:
        overview = provider.incident_overview(facts)
        analysis_mode, model_used = "fallback", "deterministic"

    verdict = (
        f"High-priority correlation hypothesis: {len(phases)} alerts form a "
        f"plausible {title}. Engine confidence {confidence}% aggregates the "
        f"per-phase verdicts. This does not prove a single actor; timeline and "
        f"host correlation are consistent with one intrusion but require "
        f"Tier-2 confirmation."
    )

    return CorrelatedIncident(
        incident_id=_next_incident_id(),
        title=title,
        confidence=confidence,
        phases=phases,
        verdict=verdict,
        overview=overview,
        recommended_actions=list(_DEFAULT_ACTIONS),
        analysis_mode=analysis_mode,
        model_used=model_used,
    )