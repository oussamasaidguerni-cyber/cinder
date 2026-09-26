from ..schemas.alerts import Alert, AlertType
from ..schemas.analysis import AnalysisResult
from .mitre import technique_for

# Keyword groups used by the raw-log detector. Order matters: SSH is checked
# first so "Failed password ... ssh2" isn't miscast as a web attack.
_DETECTORS: list[tuple[str, tuple[str, ...]]] = [
    ("SSH_BRUTE_FORCE", ("failed password", "invalid user", "sshd", "auth.log")),
    ("WEB_ATTACK", ("union select", "sql injection", "information_schema", "sqlmap", "../", "etc/passwd")),
    ("POWERSHELL_ACTIVITY", ("powershell", "scriptblock", "event_id 4104", "export-csv", "invoke-")),
    ("PHISHING", ("phishing", "spf=fail", "spf_status", "sandbox", "dkim")),
    ("OUTBOUND_CONNECTION", ("outbound", "c2", "beacon", "conncount", "dstport")),
]


def detect_type(text: str) -> str | None:
    """Guess an AlertType from freeform raw text, or None if unrecognized."""
    low = text.lower()
    for alert_type, keywords in _DETECTORS:
        if any(k in low for k in keywords):
            return alert_type
    return None

_CALLOUTS = {
    "SSH_BRUTE_FORCE": (
        ("SSH brute force", "Multiple consecutive failed SSH login attempts"),
        "HIGH",
        "Possible SSH brute-force attack. Evidence suggests an automated "
        "credential-authentication attempt against the host.",
        [
            "Review authentication logs for other hosts trying the same usernames.",
            "Check for any successful logins from the source IP.",
            "Enable fail2ban or equivalent if not already active.",
            "Require key-based authentication and disable password auth if feasible.",
        ],
        [
            "Legitimate user retyping password from a single host.",
            "Automated capacity testing or monitoring service polling SSH.",
        ],
    ),
    "POWERSHELL_ACTIVITY": (
        ("Suspicious PowerShell", "Non-standard PowerShell ScriptBlock execution"),
        "MEDIUM",
        "Evidence suggests a PowerShell script block executed with process "
        "enumeration and output redirection, which can indicate reconnaissance.",
        [
            "Correlate with Windows Event Logs (4688, 4104) and continue the process tree.",
            "Confirm whether the script is part of approved administrative tooling.",
            "Search for sibling scripts or downloads from untrusted origins.",
            "Escalate to Tier 2 if the process tree shows lateral movement.",
        ],
        [
            "Approved admin automation performing system inventory.",
            "Log source parsed a benign scheduled task.",
        ],
    ),
    "WEB_ATTACK": (
        ("Web application attack", "SQL-injection probes and admin-panel scanning"),
        "HIGH",
        "Evidence suggests an attempt to exploit a public-facing web application, "
        "consistent with pre-authentication scanning or SQL injection.",
        [
            "Review web server access logs for the source IP and adjacent requests.",
            "Check database query logs for evidence of successful injection.",
            "Block the source IP at the WAF/firewall if organizational policy allows.",
            "Search SIEM for the same IP targeting other internal hosts.",
        ],
        [
            "Vulnerability scanner operated by an approved security team.",
            "Honeypot traffic intentionally planted for detection testing.",
        ],
    ),
    "PHISHING": (
        ("Phishing attempt", "Email flagged by sandbox as phishing_likely"),
        "MEDIUM",
        "Evidence suggests a credential-phishing email targeting an internal "
        "recipient; sender authentication (SPF) failed.",
        [
            "Check whether the user clicked the link or entered credentials.",
            "Search mail gateway logs for the same sender/subject to other recipients.",
            "Report and quarantine the message per organizational policy.",
            "If credentials were entered, initiate password reset and review account activity.",
        ],
        [
            "Legitimate marketing mail mis-classified by the sandbox.",
            "Sender domain typo-squatting unrelated to credentials.",
        ],
    ),
    "OUTBOUND_CONNECTION": (
        ("Suspicious outbound connection", "Sustained outbound traffic to external host"),
        "LOW",
        "A host sustained repeated outbound connections to an external HTTPS "
        "endpoint. On its own the evidence is insufficient to conclude threat "
        "activity; patterns would need supportive context.",
        [
            "Confirm the destination belongs to a known cloud/CDN service.",
            "Review the source host for recently installed software or scheduled jobs.",
            "Check DNS logs for associated domains before escalation.",
        ],
        [
            "Normal software update or telemetry traffic.",
            "Developer machine running a long-lived build/test agent.",
        ],
    ),
}


def analyze_deterministic(alert: Alert) -> AnalysisResult:
    """Run the signature engine. The AI layer later enriches, never overrides."""
    alert_type = alert.alert_type.value
    entry = _CALLOUTS.get(alert_type)
    if entry is None:
        # Unknown alert type: conservative, honest, no fabricated MITRE mapping.
        return AnalysisResult(
            severity="LOW",
            threat_type="UNKNOWN",
            summary=(
                "Insufficient evidence to classify this alert. It does not match "
                "any known signature in the local rule set."
            ),
            confidence=20,
            evidence=[alert.raw_log],
            recommended_actions=[
                "Review the alert manually and add a signature if warranted."
            ],
            false_positive_indicators=[
                "Unclassified alert may simply be a new or benign log source."
            ],
        )

    (title, detail), severity, summary, actions, fps = entry
    technique = technique_for(alert_type)
    evidence_lines = alert.raw_log.splitlines()
    evidence = [
        line for line in evidence_lines
        if any(kw in line.lower() for kw in (
            "failed password", "union select", "export-csv", "phishing",
            "outbound", "verdict", "conncount",
        ))
    ] or evidence_lines[:3]

    summary = (
        f"{title} (evidence: {detail}) — severity {severity}. "
        f"Possible {title.lower()} activity from {alert.source_ip}; "
        f"confidence based on signature match in the local rule set."
    )

    return AnalysisResult(
        severity=severity,
        threat_type=title,
        summary=summary,
        confidence=88 if severity in ("HIGH", "CRITICAL") else 74,
        evidence=evidence,
        mitre_attack=(
            {
                "technique_id": technique.technique_id,
                "technique_name": technique.technique_name,
                "tactic": technique.tactic,
            }
            if technique
            else None
        ),
        recommended_actions=actions,
        false_positive_indicators=fps,
        incident_report=(
            f"Alert {alert.id}: {title}. Severity: {severity}. {detail}. "
            f"Source IP: {alert.source_ip}. Evidence: {' | '.join(evidence[:3])}."
        ),
        analysis_mode="deterministic",
    )