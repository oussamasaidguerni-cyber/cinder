"""Intel schema: real security-intelligence findings with full provenance.

The pipeline returns one IntelFinding per CVE. Every hop is explicit:
which authoritative source supplied which field, when it was retrieved,
whether it was fetched live or replayed from the local cache, and — crucially
— which parts are factual source data vs. engine reasoning vs. AI narration.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class AttckTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str = Field(
        description="Abbreviated technique description from MITRE ATT&CK (see url)"
    )
    technique_url: str = Field(description="Official https://attack.mitre.org page")
    basis: str = Field(
        description=(
            "Deterministic, defensible reason CINDER associated this technique "
            "(e.g. CWE class); NOT a claim that MITRE mapped this exact CVE."
        )
    )


class CvssMetric(BaseModel):
    version: str
    vector_string: str
    base_score: float
    base_severity: str
    attack_vector: str | None = None
    attack_complexity: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    scope: str | None = None
    exploitability_score: float | None = None
    impact_score: float | None = None


class AffectedProduct(BaseModel):
    cpe: str
    vendor: str | None = None
    product: str | None = None


class KevEntry(BaseModel):
    in_catalog: bool = False
    catalog_status: str = Field(
        default="UNKNOWN",
        description="IN_KEV | NOT_IN_KEV | UNKNOWN (catalog unavailable)",
    )
    catalog_date: str | None = None
    cve_id: str | None = None
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: str | None = None
    short_description: str | None = None
    required_action: str | None = None
    due_date: str | None = None
    known_ransomware_use: bool = False


class IntelVerdict(BaseModel):
    priority: str = Field(description="INFORMATIONAL | LOW | MEDIUM | HIGH | CRITICAL")
    priority_score: int = Field(ge=0, le=100)
    known_exploited: bool = False
    reasons: list[str] = Field(default_factory=list, description="explainable why-list")
    formula: str = Field(
        description="human-readable description of the deterministic calculation"
    )
    thresholds: dict[str, float] = Field(
        default_factory=dict, description="the exact, configurable thresholds used"
    )


class IntelReport(BaseModel):
    mode: str = Field(description="ai | fallback (deterministic template)")
    model_used: str | None = None
    explanation: str = ""
    why_it_matters: str = ""
    investigation: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    uncertainty: str = Field(
        default="", description="explicit 'Insufficient evidence' notes if any"
    )


class IntelMetrics(BaseModel):
    data_kind: str = Field(description="live | cached")
    cached_note: str | None = Field(
        default=None, description="e.g. 'previously retrieved from NIST NVD at ...'"
    )
    sources_consulted: list[str] = Field(default_factory=list)
    enrichment_ms: int = 0
    ai_ms: int = 0
    total_ms: int = 0


class InventoryMatch(BaseModel):
    configured: bool = False
    match_status: str = Field(
        description="NO_INVENTORY | IN_INVENTORY | NOT_IN_INVENTORY"
    )
    matched_cpes: list[str] = Field(default_factory=list)
    matched_products: list[str] = Field(default_factory=list)


class IntelFinding(BaseModel):
    cve_id: str
    data_kind: str
    retrieved_at: datetime
    source: str = "NIST NVD"

    published: str | None = None
    last_modified: str | None = None
    vuln_status: str | None = None
    description: str = ""

    cvss: CvssMetric | None = None
    cwes: list[str] = Field(default_factory=list)
    affected_products: list[AffectedProduct] = Field(default_factory=list)
    references: list[dict] = Field(
        default_factory=list, description="[{'url','source','tags'}] authoritative links"
    )

    kev: KevEntry = Field(default_factory=KevEntry)
    attck: list[AttckTechnique] = Field(default_factory=list)
    inventory: InventoryMatch | None = Field(
        default=None,
        description=(
            "Does this CVE affect the operator's configured inventory? "
            "NO_INVENTORY means we cannot say — never a fabricated hit."
        ),
    )

    verdict: IntelVerdict | None = None
    report: IntelReport | None = None
    metrics: IntelMetrics = Field(default_factory=IntelMetrics)

    sources: list[str] = Field(
        default_factory=list, description="provenance list shown in the UI"
    )


class IntelSearchResult(BaseModel):
    cve_id: str
    published: str | None = None
    base_score: float | None = None
    base_severity: str | None = None
    description: str = ""
    cwes: list[str] = Field(default_factory=list)
    kev_status: str = "UNKNOWN"
    priority: str | None = None
    data_kind: str = "live"

    def __init__(self, **data):
        super().__init__(**data)


class IntelSourcesResponse(BaseModel):
    sources: list[dict] = Field(default_factory=list)
    cache: dict = Field(default_factory=dict)


class IntelStatsResponse(BaseModel):
    processed: int
    priority_distribution: dict[str, int]
    known_exploited: int
    newest_retrieved: datetime | None = None
    kev_catalog_date: str | None = None