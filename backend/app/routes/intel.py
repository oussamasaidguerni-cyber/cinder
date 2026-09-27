"""Threat-intelligence endpoints: real NVD/KEV/ATT&CK-backed CVE intelligence.

All data is real and labeled: live vs cached, and the provenance of every
field. AI never invents — when AI is unavailable the engine verdict still
stands, and the report explicitly says so.
"""

import logging

from fastapi import APIRouter, HTTPException, Query

from ..intel.nvd import NvdError
from ..intel.pipeline import Pipeline
from ..schemas.intel import (
    IntelFinding,
    IntelSearchResult,
    IntelSourcesResponse,
    IntelStatsResponse,
)
from ..data.store import AlertStore

logging.basicConfig(level=logging.INFO)
_log = logging.getLogger("cinder.intel")

router = APIRouter(prefix="/intel", tags=["intel"])


def _pipeline():
    store = AlertStore("data/cinder.db")
    return Pipeline(store=store), store


@router.get("/search", response_model=list[IntelSearchResult])
def intel_search(q: str = Query(..., min_length=3), limit: int = Query(default=12, le=25)):
    """Search NVD by keyword. Returns the top real matches; no fabrication."""
    pipe, store = _pipeline()
    try:
        return pipe.search(q, limit=limit)
    except NvdError as exc:
        _log.warning("search failed: %s", exc)
        raise HTTPException(status_code=502, detail="NVD temporarily unavailable.") from exc
    finally:
        store.close()


@router.get("/cves/{cve_id}", response_model=IntelFinding)
def intel_cve(
    cve_id: str,
    force: bool = Query(default=False),
    use_ai: bool = Query(default=True, alias="ai"),
):
    """Full intelligence package for one CVE: sources, verdict, and (optionally)
    an AI-narrated, evidence-only report. Engine verdict never depends on AI."""
    pipe, store = _pipeline()
    try:
        finding = pipe.analyze(cve_id, force=force)
    except NvdError as exc:
        _log.warning("intel analyze failed: %s", exc)
        raise HTTPException(
            status_code=502,
            detail=(
                "Live source (NIST NVD) temporarily unavailable and no cached "
                "record exists. CINDER never fabricates intelligence."
            ),
        ) from exc
    finally:
        store.close()
    if not use_ai and finding.report and finding.report.mode == "ai":
        finding.report.mode = "skipped_ai"
        finding.report.explanation = (
            "AI narration was skipped by request; the evidence and engine "
            "verdict above are complete without it."
        )
    return finding


@router.get("/sources", response_model=IntelSourcesResponse)
def intel_sources() -> IntelSourcesResponse:
    """Provenance panel: where CINDER gets its intelligence."""
    pipe, store = _pipeline()
    try:
        return pipe.sources()
    finally:
        store.close()


@router.get("/stats", response_model=IntelStatsResponse)
def intel_stats() -> IntelStatsResponse:
    """Real counters from the processed-CVE cache."""
    pipe, store = _pipeline()
    try:
        return pipe.stats()
    finally:
        store.close()