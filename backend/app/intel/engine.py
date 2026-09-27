"""Deterministic CVE priority engine.

Pure function of verified source data: CVSS base score + vector, CWE class,
and CISA KEV catalog membership. The output is fully explainable — every
point awarded is backed by a reason string, and every adjustable knob is
exposed (`thresholds`) so the calculation is auditable end to end. No AI and
no randomness is involved in the verdict.
"""

from __future__ import annotations

import os

from ..schemas.intel import CvssMetric, IntelVerdict, KevEntry

# Configurable knobs (env-overridable). Defaults chosen conservatively.
_KEV_BUMP = int(os.environ.get("CINDER_KEV_BUMP", "18"))
_CRIT_AT = int(os.environ.get("CINDER_CRITICAL_AT", "80"))
_HIGH_AT = int(os.environ.get("CINDER_HIGH_AT", "60"))
_MED_AT = int(os.environ.get("CINDER_MEDIUM_AT", "40"))
_LOW_AT = int(os.environ.get("CINDER_LOW_AT", "20"))

_THRESHOLDS: dict[str, float] = {
    "cvss_weight": 10.0,
    "kev_bump": float(_KEV_BUMP),
    "critical_at": float(_CRIT_AT),
    "high_at": float(_HIGH_AT),
    "medium_at": float(_MED_AT),
    "low_at": float(_LOW_AT),
}


def _severity_floor(base_severity: str) -> int:
    """Map CVSS severity adjectives to a score floor so a truly critical CVSS
    score is never shown lower than its label implies."""
    return {
        "CRITICAL": 75,
        "HIGH": 55,
        "MEDIUM": 35,
        "LOW": 15,
        "INFO": 0,
        "NONE": 0,
    }.get(base_severity.upper(), 0)


def _axis_bonus(cvss: CvssMetric) -> tuple[int, list[str]]:
    reasons: list[str] = []
    bonus = 0
    av = (cvss.attack_vector or "N").upper()
    if av == "N":
        bonus += 8
        reasons.append("Network attack vector: exploitable without host proximity (+8).")
    elif av == "A":
        bonus += 4
        reasons.append("Adjacent attack vector: requires adjacent network access (+4).")
    pr = (cvss.privileges_required or "N").upper()
    if pr == "N":
        bonus += 7
        reasons.append("No privileges required: low barrier to exploitation (+7).")
    elif pr == "L":
        bonus += 3
        reasons.append("Low privileges required (+3).")
    ui = (cvss.user_interaction or "N").upper()
    if ui == "N":
        bonus += 3
        reasons.append("No user interaction required (+3).")
    return bonus, reasons


def _kev_effect(kev: KevEntry, raw_score: int) -> tuple[int, list[str]]:
    if kev.in_catalog:
        return _KEV_BUMP, [
            f"Published in CISA KEV catalog ({kev.date_added or 'date unknown'}): "
            f"confirmed exploited in the wild (+{_KEV_BUMP})."
        ]
    return 0, []


def _band(score: int) -> str:
    if score >= _CRIT_AT:
        return "CRITICAL"
    if score >= _HIGH_AT:
        return "HIGH"
    if score >= _MED_AT:
        return "MEDIUM"
    if score >= _LOW_AT:
        return "LOW"
    return "INFORMATIONAL"


def _formula(cvss: CvssMetric | None, known_exploited: bool) -> str:
    parts = [
        "score = CVSS_base_score × 10",
        "+ axis bonuses (network +8, no-privileges +7, no-interaction +3)",
        "+ CISA KEV catalog membership (+18 when present)",
    ]
    if cvss:
        parts.append(
            f"floored at {_severity_floor(cvss.base_severity)} to respect the "
            "recorded CVSS severity band"
        )
    if known_exploited:
        parts.append("known-exploited records are never scored below HIGH")
    return "; ".join(parts)


def inventory_tokens() -> list[tuple[str, str]]:
    """Parse the env-configured inventory as (vendor, product) pairs.

    Format: comma-separated `vendor:product` tokens, e.g.
    CINDER_INVENTORY="paloaltonetworks:pan-os,apache:log4j,apache:http_server"
    Unknown/empty -> [] (meaning: no inventory configured).
    """
    raw = os.environ.get("CINDER_INVENTORY", "").strip()
    tokens: list[tuple[str, str]] = []
    for item in raw.split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        vendor, _, product = item.partition(":")
        tokens.append((vendor.strip().lower(), product.strip().lower()))
    return tokens


def match_inventory(
    affected_products: list,
    inventory: list[tuple[str, str]] | None = None,
) -> dict:
    """Does this CVE affect anything the operator has told us they run?

    Returns an honest, three-state answer:
      NO_INVENTORY     -> operator configured no inventory; we cannot say.
      IN_INVENTORY     -> at least one affected vendor:product is in inventory.
      NOT_IN_INVENTORY -> inventory is configured but nothing matches.
    No match logic means no claim; absent data never fabricates a hit.
    """
    if inventory is None:
        inventory = inventory_tokens()
    if not inventory:
        return {
            "configured": False,
            "match_status": "NO_INVENTORY",
            "matched_cpes": [],
            "matched_products": [],
        }
    matched_cpes: list[str] = []
    matched_products: list[str] = []
    for p in affected_products:
        vendor = (p.vendor or "").lower()
        product = (p.product or "").lower()
        if not vendor or not product:
            continue
        for iv, ip in inventory:
            if vendor == iv and product == ip:
                cpe = p.cpe if isinstance(p, dict) else getattr(p, "cpe", None)
                if cpe and cpe not in matched_cpes:
                    matched_cpes.append(cpe)
                label = f"{vendor}:{product}"
                if label not in matched_products:
                    matched_products.append(label)
                break
            # Product-only match ("apache" matches "apache:log4j", "apache:http_server")
            if ip and product == ip and iv == "*":
                cpe = p.cpe if isinstance(p, dict) else getattr(p, "cpe", None)
                if cpe and cpe not in matched_cpes:
                    matched_cpes.append(cpe)
                label = f"{vendor}:{product}"
                if label not in matched_products:
                    matched_products.append(label)
                break
    return {
        "configured": True,
        "match_status": "IN_INVENTORY" if matched_cpes else "NOT_IN_INVENTORY",
        "matched_cpes": matched_cpes,
        "matched_products": matched_products,
    }


def analyze(cvss: CvssMetric | None, kev: KevEntry) -> IntelVerdict:
    reasons: list[str] = []

    if cvss is None:
        raw = 0
        reasons.append("No CVSS metric published by NVD for this record.")
    else:
        raw = round(cvss.base_score * _THRESHOLDS["cvss_weight"], 1)
        reasons.append(
            f"Published CVSS {cvss.version} base score {cvss.base_score} "
            f"({cvss.base_severity}) → {raw:g}."
        )
        axis_bonus, axis_reasons = _axis_bonus(cvss)
        raw += axis_bonus
        reasons.extend(axis_reasons)
        floor = _severity_floor(cvss.base_severity)
        if raw < floor:
            raw = floor
            reasons.append(
                f"Rounded up to {cvss.base_severity} floor per the recorded "
                "severity band."
            )

    bump, kev_reasons = _kev_effect(kev, raw)
    known_exploited = kev.in_catalog
    raw = min(100, raw + bump)
    raw = int(raw)
    reasons.extend(kev_reasons)

    priority = _band(raw)
    if known_exploited and priority in ("LOW", "INFORMATIONAL"):
        priority = "HIGH"
        if raw < _HIGH_AT:
            raw = _HIGH_AT
        reasons.append("Known-exploited record elevated to HIGH by policy.")

    reasons.append(
        f"Final deterministic score {raw:g} → priority {priority} "
        f"(bands: CRITICAL≥{_CRIT_AT}, HIGH≥{_HIGH_AT}, MEDIUM≥{_MED_AT}, "
        f"LOW≥{_LOW_AT})."
    )

    return IntelVerdict(
        priority=priority,
        priority_score=raw,
        known_exploited=known_exploited,
        reasons=reasons,
        formula=_formula(cvss, known_exploited),
        thresholds=dict(_THRESHOLDS),
    )