"""Intel pipeline: real source data -> explainable verdict -> AI narration.

Flow per CVE:
  1. Cache check  — fresh cached record (< CINDER_CACHE_TTL) short-circuits
     the network call. Force re-fetch with ?force=1.
  2. Live NVD     — parse NVD API v2 record (authoritative vulnerability facts).
  3. CISA KEV     — catalog is cached (< CINDER_KEV_TTL_HOURS), refreshed on
     demand; membership is the ground-truth "exploited in the wild" signal.
  4. ATT&CK       — real technique metadata associated deterministically from
     the CWE class, each with an auditable `basis`.
  5. Engine       — deterministic, explainable priority verdict (no AI).
  6. AI report    — structured narration of the VERIFIED facts only; fails
     soft to a deterministic template. Never invents.

Every returned finding carries provenance: source labels, retrieval timestamps,
and an explicit live-vs-cached flag. API failures never fabricate data — a
missing live source either serves the previous cached record (labeled) or
raises so the route returns a clear 502.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

from ..ai.provider import AIError, get_provider
from ..data.store import AlertStore
from ..schemas.intel import (
    AttckTechnique,
    IntelFinding,
    IntelMetrics,
    IntelReport,
    IntelSourcesResponse,
    IntelStatsResponse,
    InventoryMatch,
    KevEntry,
)
from . import attck
from .engine import analyze as score_cve
from .engine import match_inventory
from .kev import KevClient, KevError
from .nvd import _NvdClient, NvdError, parse_cve_json

_UTC = timezone.utc
CACHE_TTL_HOURS = float(os.environ.get("CINDER_CACHE_TTL_HOURS", "6"))
KEV_TTL_HOURS = float(os.environ.get("CINDER_KEV_TTL_HOURS", "6"))


def _cache_ttl_days() -> float:
    return float(os.environ.get("CINDER_CACHE_TTL_HOURS", "6")) / 24

_SEARCH_CACHE: dict[str, dict] = {}
_SEARCH_TTL_S = 300

_SOURCE_NVD = "NIST NVD (nvd.nist.gov / rest/json/cves/2.0)"
_SOURCE_KEV = "CISA Known Exploited Vulnerabilities Catalog"
_SOURCE_ATTACK = "MITRE ATT&CK (attack.mitre.org)"


def _now_iso() -> str:
    return datetime.now(_UTC).isoformat()


class Pipeline:
    def __init__(
        self,
        store: AlertStore,
        nvd: _NvdClient | None = None,
        kev: KevClient | None = None,
    ) -> None:
        self.store = store
        self.nvd = nvd or _NvdClient()
        self.kev = kev or KevClient()
        self.ai = get_provider()

    # -- CISA KEV catalog (cached) ------------------------------------------

    def _kev_catalog_stale(self) -> bool:
        last = self.store.intel_kev_last_fetched()
        if not last:
            return True
        try:
            ts = datetime.fromisoformat(last)
        except ValueError:
            return True
        return (datetime.now(_UTC) - ts.replace(tzinfo=_UTC)).total_seconds() > (
            KEV_TTL_HOURS * 3600
        )

    def _ensure_kev(self) -> str | None:
        """Fetch KEV catalog if missing or stale; return catalog date."""
        if not self._kev_catalog_stale():
            return self.store.intel_kev_get_released()
        catalog = self.kev.fetch_catalog()
        self.store.intel_kev_replace(catalog["entries"], catalog["dateReleased"])
        return catalog["dateReleased"]

    def _kev_status(self, cve_id: str, catalog_date: str | None):
        entry = self.store.intel_kev_get_entry(cve_id)
        if entry:
            return self.kev.to_kev_entry(entry, catalog_date)
        if catalog_date is None:
            # KEV catalog was never fetched (outage) — be honest, never assume.
            return KevEntry(in_catalog=False, catalog_status="UNKNOWN", catalog_date=None)
        return self.kev.to_kev_entry(None, catalog_date)

    # -- shared parsing -----------------------------------------------------

    def _build(
        self,
        parsed: dict,
        kev,
        verdict,
        attck_list: list[dict],
        report: IntelReport,
        data_kind: str,
        retrieved_at: datetime,
        cached_note: str | None,
        metrics: IntelMetrics,
        sources: list[str],
    ) -> IntelFinding:
        return IntelFinding(
            cve_id=parsed["_cve_id"],
            data_kind=data_kind,
            retrieved_at=retrieved_at,
            source=_SOURCE_NVD,
            published=parsed.get("published"),
            last_modified=parsed.get("last_modified"),
            vuln_status=parsed.get("vuln_status"),
            description=parsed.get("description", ""),
            cvss=parsed.get("cvss"),
            cwes=parsed.get("cwes", []),
            affected_products=parsed.get("affected_products", []),
            references=parsed.get("references", []),
            kev=kev,
            attck=[AttckTechnique(**t) for t in attck_list],
            inventory=InventoryMatch(**match_inventory(parsed.get("affected_products", []))),
            verdict=verdict,
            report=report,
            metrics=metrics,
            sources=sources,
        )

    # -- AI report, fail-soft -----------------------------------------------

    def _ai_report(self, parsed: dict, verdict) -> IntelReport:
        facts = json.dumps(
            {
                "cve_id": parsed["_cve_id"],
                "published": parsed.get("published"),
                "vuln_status": parsed.get("vuln_status"),
                "cvss": parsed.get("cvss").model_dump() if parsed.get("cvss") else None,
                "cwes": parsed.get("cwes", []),
                "affected_products": [p.model_dump() for p in parsed.get("affected_products", [])],
                "references": parsed.get("references", []),
                "kev": verdict.known_exploited,
            },
            default=str,
        )
        t0 = time.monotonic()
        try:
            if not self.ai.is_live():
                rep = self.ai.cve_report(facts, verdict.model_dump_json())
                mode, model = "fallback", None
            else:
                rep = self.ai.cve_report(facts, verdict.model_dump_json())
                mode, model = "ai", self.ai.model_name
        except AIError:
            rep = None
            mode, model = "fallback", None
        ai_ms = int((time.monotonic() - t0) * 1000)

        if rep is None:
            return (
                IntelReport(
                    mode="fallback",
                    model_used=model,
                    explanation=(
                        "Report unavailable: the live AI provider is down and "
                        "even the deterministic fallback failed. The engine "
                        "verdict above remains valid — it did not depend on AI."
                    ),
                    uncertainty="Insufficient evidence.",
                ),
                ai_ms,
            )
        return (
            IntelReport(
                mode=mode,
                model_used=model,
                explanation=rep.explanation,
                why_it_matters=rep.why_it_matters,
                investigation=rep.investigation,
                remediation=rep.remediation,
                uncertainty=rep.uncertainty,
            ),
            ai_ms,
        )

    # -- main entrypoint ----------------------------------------------------

    def analyze(self, cve_id: str, force: bool = False) -> IntelFinding:
        cve_id = cve_id.strip().upper()
        t_start = time.monotonic()
        try:
            catalog_date = self.store.intel_kev_get_released()
            if self._kev_catalog_stale():
                catalog_date = self._ensure_kev()
        except KevError:
            catalog_date = None
        sources = [_SOURCE_NVD, _SOURCE_KEV, _SOURCE_ATTACK]

        cached = self.store.intel_get_cve(cve_id) if not force else None
        if cached and self.store.intel_introspect_fresh(cve_id, _cache_ttl_days()):
            parsed = parse_cve_json(json.loads(cached["raw_record"]))
            verdict = json.loads(cached["verdict"]) if cached["verdict"] else None
            attck_list = json.loads(cached["attck"]) if cached["attck"] else []
            if cached["report"]:
                report = IntelReport(**json.loads(cached["report"]))
            else:
                report, _ai_ms = self._ai_report(parsed, verdict)
            kev = KevClient.to_kev_entry(
                json.loads(cached["kev_entry"]) if cached["kev_entry"] else None,
                cached.get("kev_catalog_date"),
            )
            kind = "cached"
            note = (
                "Replayed from the local cache — previously retrieved from "
                f"NIST NVD at {cached['retrieved_at']}. Use force=true to "
                "re-fetch live."
            )
            metrics = IntelMetrics(
                data_kind=kind,
                cached_note=note,
                sources_consulted=sources,
                total_ms=int((time.monotonic() - t_start) * 1000),
            )
            finding = self._build(
                parsed=parsed,
                kev=kev,
                verdict=verdict,
                attck_list=attck_list,
                report=report,
                data_kind=kind,
                retrieved_at=datetime.fromisoformat(cached["retrieved_at"]),
                cached_note=note,
                metrics=metrics,
                sources=sources,
            )
            self.store.intel_put_cve(
                cve_id, cached["raw_record"], cached["retrieved_at"],
                _now_iso(), cached["verdict"], cached["attck"],
                cached["kev_entry"], cached["kev_catalog_date"],
                cached["report"],
            )
            return finding

        # Live path.
        statuses: dict[str, str] = {}
        try:
            raw = self.nvd.fetch_cve(cve_id)
            statuses["nvd"] = "live"
        except NvdError as exc:
            if cached:
                # Fall back to the previous record, honestly labeled.
                parsed = parse_cve_json(json.loads(cached["raw_record"]))
                verdict = json.loads(cached["verdict"])
                attck_list = json.loads(cached["attck"]) if cached["attck"] else []
                report = (
                    IntelReport(**json.loads(cached["report"]))
                    if cached["report"] else
                    IntelReport(
                        mode="fallback",
                        explanation=(
                            "Report unavailable: live NVD fetch failed and the "
                            "AI engine had nothing new to narrate."
                        ),
                        uncertainty="Insufficient evidence.",
                    )
                )
                kev = KevClient.to_kev_entry(
                    json.loads(cached["kev_entry"]) if cached["kev_entry"] else None,
                    cached.get("kev_catalog_date"),
                )
                metrics = IntelMetrics(
                    data_kind="cached",
                    cached_note=(
                        f"NVD live fetch failed ({exc}); serving the previous "
                        f"cached record from {cached['retrieved_at']}."
                    ),
                    sources_consulted=sources,
                    total_ms=int((time.monotonic() - t_start) * 1000),
                )
                return self._build(
                    parsed=parsed, kev=kev, verdict=verdict,
                    attck_list=attck_list, report=report, data_kind="cached",
                    retrieved_at=datetime.fromisoformat(cached["retrieved_at"]),
                    cached_note=metrics.cached_note, metrics=metrics,
                    sources=sources,
                )
            raise

        parsed = parse_cve_json(raw)
        kev = self._kev_status(cve_id, catalog_date)
        attck_list = attck.techniques_for_cwes(parsed["cwes"])
        verdict = score_cve(parsed.get("cvss"), kev)
        enrichment_ms = int((time.monotonic() - t_start) * 1000)

        report, ai_ms = self._ai_report(parsed, verdict)

        fetched_at = datetime.now(_UTC)
        metrics = IntelMetrics(
            data_kind="live",
            sources_consulted=sources,
            enrichment_ms=enrichment_ms,
            ai_ms=ai_ms,
            total_ms=int((time.monotonic() - t_start) * 1000),
        )
        finding = self._build(
            parsed=parsed, kev=kev, verdict=verdict, attck_list=attck_list,
            report=report, data_kind="live", retrieved_at=fetched_at,
            cached_note=None, metrics=metrics, sources=sources,
        )
        self.store.intel_put_cve(
            cve_id=cve_id,
            raw_record=json.dumps(raw),
            retrieved_at=fetched_at.isoformat(),
            last_checked=_now_iso(),
            verdict=verdict.model_dump_json(),
            attck=json.dumps(attck_list),
            kev_entry=json.dumps(
                {k: v for k, v in kev.model_dump().items()
                 if k not in ("in_catalog", "catalog_status", "catalog_date")}
            ) if kev.in_catalog else None,
            kev_catalog_date=catalog_date,
            report=report.model_dump_json(),
        )
        return finding

    # -- search / sources / stats -------------------------------------------

    def search(self, query: str, limit: int = 12) -> list:
        key = query.strip().lower()
        cached_hit = _SEARCH_CACHE.get(key)
        if cached_hit and time.monotonic() - cached_hit["ts"] < _SEARCH_TTL_S:
            return cached_hit["results"]
        try:
            self._ensure_kev()
            catalog_ok = True
        except KevError:
            catalog_ok = False
        results = self.nvd.search(query, limit=limit)
        for r in results:
            entry = self.store.intel_kev_get_entry(r.cve_id)
            if entry:
                r.kev_status = "IN_KEV"
            elif not catalog_ok:
                r.kev_status = "UNKNOWN"
            else:
                r.kev_status = "NOT_IN_KEV"
        _SEARCH_CACHE[key] = {"ts": time.monotonic(), "results": results}
        return results

    def sources(self) -> IntelSourcesResponse:
        kev_date = self.store.intel_kev_get_released()
        return IntelSourcesResponse(
            sources=[
                {
                    "name": "NIST NVD",
                    "kind": "live",
                    "url": "https://nvd.nist.gov",
                    "note": "Authoritative CVE records (MITRE-assigned). "
                            "Fetched live per lookup; cached for 6h.",
                },
                {
                    "name": "CISA KEV Catalog",
                    "kind": "catalog",
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "catalog_date": kev_date,
                    "note": "Ground-truth 'exploited in the wild'. Catalog "
                            "refreshed at most every 6h.",
                },
                {
                    "name": "MITRE ATT&CK",
                    "kind": "reference",
                    "url": "https://attack.mitre.org",
                    "note": "Technique metadata is real; the CVE->technique "
                            "association is CINDER's deterministic reasoning "
                            "from the CWE class, shown with its basis.",
                },
            ],
            cache={
                "cve_count": self.store.intel_cve_count(),
                "kev_catalog_date": kev_date,
                "kev_last_fetched": self.store.intel_kev_last_fetched(),
            },
        )

    def stats(self) -> IntelStatsResponse:
        rows = self.store.intel_cves()
        dist: dict[str, int] = {}
        known = 0
        newest: datetime | None = None
        for row in rows:
            try:
                verdict = json.loads(row["verdict"]) if row["verdict"] else {}
            except (json.JSONDecodeError, TypeError):
                verdict = {}
            priority = verdict.get("priority", "UNKNOWN")
            dist[priority] = dist.get(priority, 0) + 1
            if verdict.get("known_exploited"):
                known += 1
            try:
                ts = datetime.fromisoformat(row["retrieved_at"])
            except ValueError:
                continue
            if newest is None or ts > newest:
                newest = ts
        return IntelStatsResponse(
            processed=self.store.intel_cve_count(),
            priority_distribution=dict(sorted(dist.items(), key=lambda kv: kv[1], reverse=True)),
            known_exploited=known,
            newest_retrieved=newest,
            kev_catalog_date=self.store.intel_kev_get_released(),
        )