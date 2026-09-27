"""Demo alert seed data. All fixtures are fabricated for a hackathon demo.

IPs use RFC 5737 TEST-NET ranges (203.0.113.0/24, 198.51.100.0/24) which are
reserved for documentation and cannot belong to real infrastructure.
No real credentials, real malware, or real attack infrastructure are used.
"""

from datetime import datetime, timedelta, timezone

from ..schemas.alerts import Alert, AlertStatus, AlertType, Severity

_UTC = timezone.utc


def _seed() -> list[Alert]:
    now = datetime.now(_UTC)
    return [
        Alert(
            id="AL-2024-0001",
            timestamp=now - timedelta(minutes=42),
            source="sshd[31861]",
            source_ip="203.0.113.45",
            destination="10.20.0.5:22",
            alert_type=AlertType.SSH_BRUTE_FORCE,
            severity=Severity.HIGH,
            status=AlertStatus.NEW,
            raw_log=(
                "Mar 10 23:14:11 srv-web sshd[31861]: Failed password for invalid "
                "user root from 203.0.113.45 port 59214 ssh2\n"
                "Mar 10 23:14:13 srv-web sshd[31861]: Failed password for invalid "
                "user root from 203.0.113.45 port 59218 ssh2\n"
                "Mar 10 23:14:15 srv-web sshd[32010]: Failed password for admin from "
                "203.0.113.45 port 59224 ssh2\n"
                "Mar 10 23:14:17 srv-web sshd[32014]: Failed password for user admin "
                "from 203.0.113.45 port 59231 ssh2\n"
                "Mar 10 23:14:19 srv-web sshd[32098]: Failed password for user ubuntu "
                "from 203.0.113.45 port 59244 ssh2\n"
                "Mar 10 23:15:02 srv-web sshd[32110]: Failed password for invalid "
                "user postgres from 203.0.113.45 port 59302 ssh2"
            ),
            description="Repeated failed SSH login attempts from a single host.",
        ),
        Alert(
            id="AL-2024-0002",
            timestamp=now - timedelta(minutes=18),
            source="WinEventLog: Security",
            source_ip="198.51.100.23",
            destination="10.20.0.12",
            alert_type=AlertType.POWERSHELL_ACTIVITY,
            severity=Severity.MEDIUM,
            status=AlertStatus.NEW,
raw_log=(
                '{"protocol": "winevent", "event_id": 4104, "host": "DC-01", '
                '"message": "ScriptBlock text running at host DC-01: '
                'Get-Process | Where-Object { $_.ProcessName -match \\"winlogon|svchost\\" } '
                '| Export-Csv C:\\\\temp\\\\procs.csv", '
                '"source_ip": "198.51.100.23"}'
            ),
            description="PowerShell ScriptBlock logging detected suspicious script execution.",
        ),
        Alert(
            id="AL-2024-0003",
            timestamp=now - timedelta(minutes=7),
            source="nginx access.log",
            source_ip="198.51.100.99",
            destination="10.20.0.5:443",
            alert_type=AlertType.WEB_ATTACK,
            severity=Severity.HIGH,
            status=AlertStatus.NEW,
            raw_log=(
                '198.51.100.99 - - [10/Mar/2024:23:18:02 +0000] '
                '"GET /product?id=1%27%20UNION%20SELECT%20username,password%20'
                "FROM%20users-- HTTP/1.1\" 400 182 \"-\" \"Mozilla/5.0\"\n"
                '198.51.100.99 - - [10/Mar/2024:23:18:05 +0000] '
                '"GET /admin.jsp HTTP/1.1\" 401 311 \"-\" \"Mozilla/5.0\"'
            ),
            description="SQL injection probes and admin panel discovery in web access logs.",
        ),
        Alert(
            id="AL-2024-0004",
            timestamp=now - timedelta(minutes=3),
            source="EDR email gateway",
            source_ip="203.0.113.88",
            destination="user@company.local",
            alert_type=AlertType.PHISHING,
            severity=Severity.MEDIUM,
            status=AlertStatus.NEW,
            raw_log=(
                '[Alert] SMTP sandbox flagged message: sender=notify@example.net, '
                'subject="URGENT: Verify your account", attachment=Invoice_2847.zip, '
                'links=[https://example.com/verify/account?id=8842], '
                "dns_mx_status=pass, spf_status=fail, dkim_status=neutral, "
                "verdict=phishing_likely"
            ),
            description="Email with indicators consistent with credential phishing.",
        ),
        Alert(
            id="AL-2024-0005",
            timestamp=now - timedelta(minutes=1),
            source="FW-EDGE (firewall)",
            source_ip="10.20.0.31",
            destination="203.0.113.200:443",
            alert_type=AlertType.OUTBOUND_CONNECTION,
            severity=Severity.LOW,
            status=AlertStatus.NEW,
            raw_log=(
                "INFO CEF:0|Fortinet|FortiGate|v7|outbound|connections|"
                "src=10.20.0.31 dst=203.0.113.200 sport=50123 dport=443 "
                "proto=tcp out=1.2MB in=0.1MB conncount=47"
            ),
            description="Sustained outbound connection to an external destination.",
        ),
    ]


def seed_alerts() -> list[Alert]:
    seeded = _seed()
    for a in seeded:
        if "[SYNTHETIC]" not in a.description:
            a.description = f"{a.description} [SYNTHETIC seed]"
    return seeded