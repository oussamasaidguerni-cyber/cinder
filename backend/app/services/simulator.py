"""Simulated alert injection for live demos. All fixtures are fabricated.

IPs use RFC 5737 TEST-NET ranges reserved for documentation so nothing here
points at real infrastructure. The verdict comes from the same deterministic
engine as every other alert, so simulated alerts behave exactly like real ones.
"""

import random
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

_POOL = [
    {
        "source": "sshd[41231]",
        "source_ip": "203.0.113.144",
        "destination": "10.20.0.7:22",
        "raw_log": (
            "Apr 12 02:11:03 edge sshd[41231]: Failed password for invalid user "
            "backup from 203.0.113.144 port 60811 ssh2\n"
            "Apr 12 02:11:05 edge sshd[41231]: Failed password for invalid user "
            "mysql from 203.0.113.144 port 60817 ssh2\n"
            "Apr 12 02:11:08 edge sshd[41231]: Failed password for root from "
            "203.0.113.144 port 60822 ssh2\n"
            "Apr 12 02:11:11 edge sshd[41231]: Failed password for invalid user "
            "guest from 203.0.113.144 port 60829 ssh2"
        ),
        "description": "New host hammering SSH with common usernames.",
    },
    {
        "source": "nginx access.log",
        "source_ip": "198.51.100.31",
        "destination": "10.20.0.5:443",
        "raw_log": (
            '198.51.100.31 - - [12/Apr/2024:02:13:40 +0000] '
            '"GET /product?id=5%27%20OR%201%3D1-- HTTP/1.1" 200 912 "-" "curl/8"'
        ),
        "description": "Boolean-based SQLi probe detected in a web request.",
    },
    {
        "source": "EDR endpoint telemetry",
        "source_ip": "198.51.100.44",
        "destination": "10.20.0.14",
        "raw_log": (
            '{"host": "WS-03", "event_id": 4688, "process": "cmd.exe", '
            '"command": "C:\\\\Windows\\\\System32\\\\cmd.exe /c powershell -enc '
            'SQBFAFgA", "source_ip": "198.51.100.44"}'
        ),
        "description": "Command line shows base64-encoded PowerShell execution.",
    },
    {
        "source": "FW-EDGE (firewall)",
        "source_ip": "10.20.0.22",
        "destination": "203.0.113.250:443",
        "raw_log": (
            "INFO CEF:0|Fortinet|FortiGate|v7|gossip-conn|connections|"
            "src=10.20.0.22 dst=203.0.113.250 sport=51234 dport=443 "
            "proto=tcp out=3.4MB in=0.2MB conncount=129"
        ),
        "description": "New sustained beacon-like outbound connection pattern.",
    },
    {
        "source": "SMTP relay",
        "source_ip": "203.0.113.60",
        "destination": "hr@company.local",
        "raw_log": (
            "[Alert] SMTP sandbox flagged message: sender=hr@secure-note.example, "
            'subject="Shared folder access required", attachment=salary_update.zip, '
            "spf_status=fail, dkim_status=neutral, verdict=phishing_likely"
        ),
        "description": "Attachment-driven phishing attempt at the gateway.",
    },
]


def simulate_alert(store: AlertStore) -> Alert:
    sample = random.choice(_POOL)
    detected = detect_type(sample["raw_log"])
    try:
        alert_type = AlertType(detected)
        severity = _SEVERITY_BY_TYPE[alert_type]
    except (ValueError, KeyError):
        alert_type, severity = AlertType.OUTBOUND_CONNECTION, Severity.LOW
    return store.create_alert(
        Alert(
            id=store.next_id(),
            timestamp=datetime.now(_UTC),
            source=sample["source"],
            source_ip=sample["source_ip"],
            destination=sample["destination"],
            alert_type=alert_type,
            severity=severity,
            status=AlertStatus.NEW,
            raw_log=sample["raw_log"],
            description=f"{sample['description']} [SYNTHETIC]",
        )
    )