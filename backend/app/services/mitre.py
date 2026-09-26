"""Local verified MITRE ATT&CK mapping.

Kept intentionally small and verified by hand. The MVP only maps the alert
types we actually ship demo data for; anything else returns null rather than
guess. See https://attack.mitre.org.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    technique_id: str
    technique_name: str
    tactic: str


# Alert type -> MITRE technique. Assignments verified against MITRE ATT&CK
# knowledge base (Enterprise matrix):
#   SSH brute force     -> T1110 Brute Force (Credential Access)
#   PowerShell script   -> T1059.001 Command and Scripting Interpreter: PowerShell
#   Web app SQLi/probe -> T1190 Exploit Public-Facing Application (Initial Access)
#   Phishing email      -> T1566 Phishing (Initial Access)
#   Outbound C2-like    -> T1071.001 Application Layer Protocol
_SSH = Technique("T1110", "Brute Force", "Credential Access")
_PS = Technique("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution")
_WEB = Technique("T1190", "Exploit Public-Facing Application", "Initial Access")
_PHISH = Technique("T1566.002", "Phishing: Spearphishing Link", "Initial Access")
_C2 = Technique("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control")

MITRE_MAP: dict[str, Technique] = {
    "SSH_BRUTE_FORCE": _SSH,
    "POWERSHELL_ACTIVITY": _PS,
    "WEB_ATTACK": _WEB,
    "PHISHING": _PHISH,
    "OUTBOUND_CONNECTION": _C2,
}


def technique_for(alert_type: str) -> Technique | None:
    return MITRE_MAP.get(alert_type)