"""CISA Known Exploited Vulnerabilities catalog.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
The catalog is small (~1-2MB) and JSON-flat, so we fetch the whole feed and
cache it in SQLite keyed by CVE id. KEV is the ground-truth signal for
"exploited in the wild", which is exactly the vulnerability-vs-intrusion
distinction the demo must keep honest.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request

from ..schemas.intel import KevEntry

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_TTL_HOURS = float(os.environ.get("CINDER_KEV_TTL_HOURS", "6"))


class KevError(RuntimeError):
    pass


class KevClient:
    def __init__(self, url: str = KEV_URL):
        self.url = url

    def fetch_catalog(self) -> dict:
        """Return {'dateReleased': str, 'entries': {cve_id: entry_dict}}."""
        try:
            with urllib.request.urlopen(self.url, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:  # urlopen can raise many network types
            raise KevError(f"CISA KEV feed unavailable: {e}") from e
        entries: dict[str, dict] = {}
        for v in data.get("vulnerabilities") or []:
            cve_id = (v.get("cveID") or "").strip().upper()
            if cve_id:
                entries[cve_id] = {
                    "cve_id": cve_id,
                    "vendor_project": v.get("vendorProject"),
                    "product": v.get("product"),
                    "vulnerability_name": v.get("vulnerabilityName"),
                    "date_added": v.get("dateAdded"),
                    "short_description": v.get("shortDescription"),
                    "required_action": v.get("requiredAction"),
                    "due_date": v.get("dueDate"),
                    "known_ransomware_use": bool(v.get("knownRansomwareCampaignUse")),
                }
        return {"dateReleased": data.get("dateReleased"), "entries": entries}

    @staticmethod
    def to_kev_entry(entry: dict | None, catalog_date: str | None) -> KevEntry:
        if not entry:
            return KevEntry(
                in_catalog=False,
                catalog_status="NOT_IN_KEV",
                catalog_date=catalog_date,
                known_ransomware_use=False,
            )
        return KevEntry(
            in_catalog=True,
            catalog_status="IN_KEV",
            catalog_date=catalog_date,
            **entry,
        )