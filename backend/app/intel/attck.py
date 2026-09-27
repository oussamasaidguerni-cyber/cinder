"""MITRE ATT&CK technique metadata + a defensible CWE-to-technique association.

Two distinct concerns are deliberately kept apart:

1. Technique metadata (IDs, names, tactics, short descriptions, canonical URLs)
   is REAL, from MITRE ATT&CK (public knowledge base, https://attack.mitre.org).
   It is embedded locally so the runtime never pulls the ~20MB STIX feed.

2. The CVE -> technique / CWE -> technique association below is CINDER's own
   deterministic reasoning from the vulnerability class. MITRE does not publish
   per-CVE ATT&CK mappings for vulnerabilities in this feed, so claiming the
   TID "is the MITRE mapping for this CVE" would be fabrication. Instead every
   association carries a `basis` that explains *why* the class is consistent
   with the technique. Unrecognized CWE IDs return no technique (never random).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class TechniqueMeta:
    technique_id: str
    technique_name: str
    tactic: str
    short: str
    url: str


_ATTACK_BASE = "https://attack.mitre.org/techniques"

TECHNIQUES: dict[str, TechniqueMeta] = {
    "T1190": TechniqueMeta(
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        "Adversaries exploit a weakness in an Internet-facing system to gain initial access.",
        f"{_ATTACK_BASE}/T1190",
    ),
    "T1210": TechniqueMeta(
        "T1210",
        "Exploitation of Remote Services",
        "Lateral Movement",
        "Adversaries exploit a remote service (e.g. network listeners) to establish a foothold.",
        f"{_ATTACK_BASE}/T1210",
    ),
    "T1203": TechniqueMeta(
        "T1203",
        "Exploitation for Client Execution",
        "Execution",
        "Adversaries exploit a client-side weakness, often via a crafted document or web content.",
        f"{_ATTACK_BASE}/T1203",
    ),
    "T1068": TechniqueMeta(
        "T1068",
        "Exploitation for Privilege Escalation",
        "Privilege Escalation",
        "Adversaries exploit a vulnerability to gain higher privileges than the account allows.",
        f"{_ATTACK_BASE}/T1068",
    ),
    "T1078": TechniqueMeta(
        "T1078",
        "Valid Accounts",
        "Defense Evasion",
        "Adversaries use legitimate credentials or accounts to operate invisibly.",
        f"{_ATTACK_BASE}/T1078",
    ),
    "T1059": TechniqueMeta(
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        "Adversaries abuse command and script interpreters to execute code.",
        f"{_ATTACK_BASE}/T1059",
    ),
    "T1059.001": TechniqueMeta(
        "T1059.001",
        "Command and Scripting Interpreter: PowerShell",
        "Execution",
        "Adversaries abuse PowerShell to execute commands or load script engine libraries.",
        f"{_ATTACK_BASE}/T1059/001",
    ),
    "T1110": TechniqueMeta(
        "T1110",
        "Brute Force",
        "Credential Access",
        "Adversaries systematically guess or crack accounts/keys to gain access.",
        f"{_ATTACK_BASE}/T1110",
    ),
    "T1505.003": TechniqueMeta(
        "T1505.003",
        "Server Software Component: Web Shell",
        "Persistence",
        "Adversaries backdoor a web server by placing a web shell.",
        f"{_ATTACK_BASE}/T1505/003",
    ),
    "T1005": TechniqueMeta(
        "T1005",
        "Data from Local System",
        "Collection",
        "Adversaries search local systems for sensitive data to exfiltrate.",
        f"{_ATTACK_BASE}/T1005",
    ),
    "T1567": TechniqueMeta(
        "T1567",
        "Exfiltration Over Web Service",
        "Exfiltration",
        "Adversaries exfiltrate data via a legitimate web service protocol.",
        f"{_ATTACK_BASE}/T1567",
    ),
    "T1213": TechniqueMeta(
        "T1213",
        "Data from Information Repositories",
        "Collection",
        "Adversaries collect sensitive info from shared repositories/databases.",
        f"{_ATTACK_BASE}/T1213",
    ),
    "T1498": TechniqueMeta(
        "T1498",
        "Network Denial of Service",
        "Impact",
        "Adversaries flood network resources to deny service to legitimate users.",
        f"{_ATTACK_BASE}/T1498",
    ),
    "T1562": TechniqueMeta(
        "T1562",
        "Impair Defenses",
        "Defense Evasion",
        "Adversaries disable or misconfigure defenses to evade detection.",
        f"{_ATTACK_BASE}/T1562",
    ),
}

# CWE class -> shortest defensible association. `basis` is deterministic prose
# shown verbatim in the "why" UI so the reasoning is auditable.
def _map(cwe: str) -> tuple[str, str] | None:
    return _CWE_TO_TECHNIQUE.get(cwe)


_CWE_TO_TECHNIQUE: dict[str, tuple[str, str]] = {
    # Injection classes against public-facing services -> initial access via exploit.
    "CWE-89": (
        "T1190",
        "CWE-89 (SQL injection) in a product reachable from a network boundary matches "
        "the exploitation pattern of T1190 Exploit Public-Facing Application.",
    ),
    "CWE-20": (
        "T1190",
        "CWE-20 (improper input validation) reachable without strong access controls is "
        "consistent with T1190 Exploit Public-Facing Application.",
    ),
    "CWE-918": (
        "T1190",
        "CWE-918 (server-side request forgery) against exposed services matches the "
        "pattern of T1190 Exploit Public-Facing Application.",
    ),
    "CWE-79": (
        "T1203",
        "CWE-79 (cross-site scripting) requires induced client-side execution, "
        "consistent with T1203 Exploitation for Client Execution.",
    ),
    "CWE-502": (
        "T1203",
        "CWE-502 (deserialization of untrusted data) typically triggers code execution "
        "via a crafted payload, consistent with T1203/T1210 exploitation.",
    ),
    "CWE-611": (
        "T1203",
        "CWE-611 (improper restriction of XXE) can cause local file disclosure and "
        "impact, consistent with client/system exploitation patterns.",
    ),
    "CWE-787": (
        "T1210",
        "CWE-787 (out-of-bounds write / memory corruption) in a service listening "
        "remotely is consistent with T1210 Exploitation of Remote Services.",
    ),
    "CWE-119": (
        "T1210",
        "CWE-119 (buffer over-read/write) memory-safety class matches T1210 "
        "Exploitation of Remote Services when a network listener is involved.",
    ),
    "CWE-120": (
        "T1210",
        "CWE-120 (buffer copy without bounds) maps to T1210 for exploitable listeners.",
    ),
    "CWE-125": (
        "T1210",
        "CWE-125 (out-of-bounds read) can be exploited over a network listener; "
        "consistent with T1210.",
    ),
    "CWE-416": (
        "T1210",
        "CWE-416 (use-after-free) is a memory-safety flaw consistent with T1210 "
        "when processed remotely.",
    ),
    "CWE-476": (
        "T1210",
        "CWE-476 (NULL pointer dereference) impacting a remote service matches "
        "T1210 exploitation patterns.",
    ),
    "CWE-22": (
        "T1505.003",
        "CWE-22 (path traversal) allowing file write/upload is frequently chained to "
        "deploy a web shell, consistent with T1505.003.",
    ),
    "CWE-434": (
        "T1505.003",
        "CWE-434 (unrestricted file upload) enables web-shell deployment, "
        "consistent with T1505.003.",
    ),
    "CWE-798": (
        "T1078",
        "CWE-798 (hard-coded credentials) is consistent with abuse of T1078 Valid Accounts.",
    ),
    "CWE-287": (
        "T1078",
        "CWE-287 (weak authentication) lowers the bar for T1078 Valid Accounts abuse.",
    ),
    "CWE-306": (
        "T1078",
        "CWE-306 (missing authentication) removes the need to crack anything; "
        "consistent with T1078 Valid Accounts.",
    ),
    "CWE-307": (
        "T1110",
        "CWE-307 (restriction of failed login attempts) is a brute-force mitigation "
        "gap, consistent with T1110 Brute Force.",
    ),
    "CWE-77": (
        "T1059",
        "CWE-77 (command injection) enables arbitrary command execution, "
        "consistent with T1059 Command and Scripting Interpreter.",
    ),
    "CWE-78": (
        "T1059",
        "CWE-78 (OS command injection) matches T1059 Command and Scripting Interpreter.",
    ),
    "CWE-94": (
        "T1059",
        "CWE-94 (code injection) allows arbitrary code execution via "
        "T1059 Command and Scripting Interpreter.",
    ),
    "CWE-400": (
        "T1498",
        "CWE-400 (resource exhaustion) degrades availability, consistent with "
        "T1498 Network Denial of Service.",
    ),
    "CWE-770": (
        "T1498",
        "CWE-770 (unbounded resource allocation) matches T1498 Network Denial of Service.",
    ),
    "CWE-862": (
        "T1078",
        "CWE-862 (missing authorization) is consistent with T1078 Valid Accounts abuse.",
    ),
    "CWE-863": (
        "T1078",
        "CWE-863 (incorrect authorization) matches the T1078 pattern.",
    ),
    "CWE-200": (
        "T1005",
        "CWE-200 (information exposure) facilitates collection, consistent with "
        "T1005 Data from Local System.",
    ),
    "CWE-552": (
        "T1005",
        "CWE-552 (files accessible to external parties) enables "
        "T1005 Data from Local System.",
    ),
    "CWE-209": (
        "T1005",
        "CWE-209 (information exposure through error messages) is consistent with "
        "collection-oriented techniques such as T1005.",
    ),
}


def techniques_for_cwes(cwes: list[str]) -> list[dict]:
    """Return [{id, name, tactic, description, url, basis}] for known CWE IDs.

    Drops unknown CWEs entirely (honesty over guessing) and deduplicates by
    technique id. The first CWE that maps to a technique wins, so the basis
    stays attributable to a single class.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for cwe in cwes:
        mapped = _map(cwe)
        if not mapped:
            continue
        tid, basis = mapped
        if tid in seen:
            continue
        meta = TECHNIQUES.get(tid)
        if not meta:
            continue
        seen.add(tid)
        out.append(
            {
                "technique_id": tid,
                "technique_name": meta.technique_name,
                "tactic": meta.tactic,
                "description": meta.short,
                "technique_url": meta.url,
                "basis": basis,
            }
        )
    return out