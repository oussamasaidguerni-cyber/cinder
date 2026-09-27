"""NIST NVD API v2 client.

Fetches real CVE records from https://services.nvd.nist.gov. Anonymous tier is
rate limited (~5 requests / 30s), so we throttle and honour 429 Retry-After.
Parsing is defensive: newer records may carry v4 metrics, older ones v2/v3.1,
and some fields are missing entirely.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from ..schemas.intel import (
    AffectedProduct,
    CvssMetric,
    IntelSearchResult,
)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdError(RuntimeError):
    pass


class _NvdClient:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self._last_request_at = 0.0
        self._min_interval = 4.0 if not self.api_key else 0.6

    def _throttle(self) -> None:
        wait = self._last_request_at + self._min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last_request_at = time.monotonic()

    def _request(self, params: dict) -> dict:
        self._throttle()
        url = f"{NVD_BASE}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url)
        if self.api_key:
            req.add_header("apiKey", self.api_key)
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 2:
                    retry = float(e.headers.get("Retry-After", "6") or 6)
                    time.sleep(min(retry, 15))
                    continue
                raise NvdError(f"NVD HTTP {e.code}: {e.reason}") from e
            except urllib.error.URLError as e:
                raise NvdError(f"NVD unreachable: {e.reason}") from e
        raise NvdError("NVD request failed after retries")

    def fetch_cve(self, cve_id: str) -> dict:
        cve_id = cve_id.strip().upper()
        data = self._request({"cveId": cve_id})
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            raise NvdError(f"NVD returned no record for {cve_id}")
        return vulns[0]["cve"]

    def search(self, query: str, limit: int = 12) -> list[dict]:
        data = self._request({"keywordSearch": query, "resultsPerPage": str(limit)})
        records = []
        for vuln in data.get("vulnerabilities") or []:
            raw = vuln.get("cve") or {}
            rec = parse_cve_json(raw)
            rec.pop("references", None)
            rec.pop("affected_products", None)
            cvss = rec.get("cvss")
            search = IntelSearchResult(
                cve_id=rec["_cve_id"],
                published=rec.get("published"),
                base_score=cvss.base_score if cvss else None,
                base_severity=cvss.base_severity if cvss else None,
                description=rec.get("description", ""),
                cwes=rec.get("cwes", []),
                data_kind="live",
            )
            records.append(search)
        return records


def _pick_metric(metrics: dict) -> dict | None:
    """Prefer the newest primary metric block available (v4 -> v3.1 -> v3.0 -> v2)."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        blocks = metrics.get(key) or []
        primary = [b for b in blocks if (b.get("type") or "") == "Primary"] or blocks
        if primary and primary[0].get("cvssData"):
            data = primary[0]["cvssData"]
            return {
                "version": data.get("version") or key,
                "vector_string": data.get("vectorString") or "",
                "base_score": float(data.get("baseScore") or 0),
                "base_severity": data.get("baseSeverity") or (
                    "LOW" if float(data.get("baseScore") or 0) < 4 else "MEDIUM"
                ),
                "attack_vector": data.get("attackVector"),
                "attack_complexity": data.get("attackComplexity"),
                "privileges_required": data.get("privilegesRequired"),
                "user_interaction": data.get("userInteraction"),
                "scope": data.get("scope"),
                "exploitability_score": primary[0].get("exploitabilityScore"),
                "impact_score": primary[0].get("impactScore"),
            }
    return None


def _parse_cwes(weaknesses: list | None) -> list[str]:
    cwes: list[str] = []
    for w in weaknesses or []:
        for d in w.get("description") or []:
            val = (d.get("value") or "").strip()
            if val.startswith("CWE-") and val not in cwes:
                cwes.append(val)
    return cwes


def _parse_products(configurations: list | None) -> list[AffectedProduct]:
    products: list[AffectedProduct] = []

    def walk(node: dict) -> None:
        for cpe in node.get("cpeMatch") or []:
            crit = cpe.get("criteria") or ""
            if not crit:
                continue
            parts = crit.split(":")
            # cpe:2.3:a:vendor:product:version:...
            if len(parts) < 6 or parts[0] != "cpe":
                continue
            vendor = parts[3] or None
            product = parts[4] or None
            if product:
                products.append(AffectedProduct(cpe=crit, vendor=vendor, product=product))
        for child in node.get("nodes") or []:
            walk(child)

    for cfg in configurations or []:
        walk(cfg)
    return products


def _parse_refs(references: list | None) -> list[dict]:
    out: list[dict] = []
    tags_by_url: dict[str, list[str]] = {}
    for ref in references or []:
        url = ref.get("url") or ""
        if not url:
            continue
        tags = tags_by_url.setdefault(url, [])
        for tag in ref.get("tags") or []:
            if tag not in tags:
                tags.append(tag)
    for url, tags in tags_by_url.items():
        out.append({"url": url, "tags": tags})
    return out


def parse_cve_json(raw: dict) -> dict:
    """Normalize one raw NVD CVE object into our internal dict shape."""
    descriptions = raw.get("descriptions") or []
    description = next(
        (d.get("value") or "" for d in descriptions if d.get("lang") == "en"),
        "",
    )
    refs = _parse_refs(raw.get("references"))
    metrics = _pick_metric(raw.get("metrics") or {})
    cwes = _parse_cwes(raw.get("weaknesses"))
    products = _parse_products(raw.get("configurations"))
    return {
        "_cve_id": raw.get("id") or "",
        "published": raw.get("published"),
        "last_modified": raw.get("lastModified"),
        "vuln_status": raw.get("vulnStatus"),
        "description": description,
        "cvss": CvssMetric(**metrics) if metrics else None,
        "cwes": cwes,
        "affected_products": products,
        "references": refs,
        "_metrics_source": "NVD",
    }