"""Intel-layer tests.

Verifies deterministic scoring, NVD parsing, CWE->ATT&CK reasoning, the
pipeline's live-vs-cached behavior, and the no-fabrication guarantees.
Network calls are replaced with fakes; real-source behavior is covered by a
single optional live test that self-skips when the API is unreachable.
"""

from datetime import datetime, timezone

import json

import pytest

from app.ai.provider import MockProvider
from app.data.store import AlertStore
from app.intel import attck
from app.intel.engine import analyze as score_cve
from app.intel.engine import match_inventory
from app.intel.nvd import parse_cve_json
from app.intel.pipeline import Pipeline
from app.schemas.intel import CvssMetric, IntelFinding, IntelMetrics, IntelSearchResult, KevEntry
from app.services.ingestion import ingest_raw_log


# ---------------------------------------------------------------------------
# fixture NVD record (shape mirrors the real API v2)
# ---------------------------------------------------------------------------

_NVD_SAMPLE = {
    "id": "CVE-2021-44228",
    "published": "2021-12-10T10:15:00",
    "lastModified": "2024-03-27T20:02:00",
    "vulnStatus": "Analyzed",
    "descriptions": [
        {"lang": "en", "value": "Apache Log4j2 <2.15.0 JNDI features allow RCE."}
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "baseScore": 10.0,
                    "baseSeverity": "CRITICAL",
                    "attackVector": "NETWORK",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                    "scope": "CHANGED",
                },
                "exploitabilityScore": 3.9,
                "impactScore": 6.0,
            }
        ]
    },
    "weaknesses": [
        {"type": "Primary", "description": [{"lang": "en", "value": "CWE-502"}]},
        {"type": "Primary", "description": [{"lang": "en", "value": "CWE-20"}]},
    ],
    "references": [
        {"url": "https://logging.apache.org/log4j/2.x/security.html", "tags": ["vendor-advisory"]}
    ],
    "configurations": [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
                        }
                    ],
                }
            ]
        }
    ],
}

_KEV_ENTRY = {
    "cve_id": "CVE-2021-44228",
    "vendor_project": "Apache",
    "product": "Log4j",
    "vulnerability_name": "Apache Log4j2 JNDI exploit",
    "date_added": "2021-12-10",
    "short_description": "RCE in Log4j2",
    "required_action": "Apply vendor updates.",
    "due_date": "2021-12-24",
    "known_ransomware_use": False,
}


class FakeNvd:
    def __init__(self, raise_on: list[str] | None = None):
        self.calls = 0
        self.raise_on = raise_on or []

    def fetch_cve(self, cve_id):
        self.calls += 1
        if cve_id in self.raise_on:
            from app.intel.nvd import NvdError

            raise NvdError("fake outage")
        return json.loads(json.dumps(_NVD_SAMPLE))

    def search(self, query, limit=12):
        return [
            IntelSearchResult(
                cve_id="CVE-2021-44228",
                base_score=10.0,
                base_severity="CRITICAL",
                description="Apache Log4j2 JNDI features allow RCE.",
                cwes=["CWE-502"],
                data_kind="live",
            )
        ]


class FakeKev:
    def __init__(self, entries: dict | None = None):
        self.entries = entries or {"CVE-2021-44228": _KEV_ENTRY}

    def fetch_catalog(self):
        return {"dateReleased": "2024.05.01", "entries": self.entries}

    def to_kev_entry(self, entry, catalog_date):
        from app.intel.kev import KevClient

        return KevClient.to_kev_entry(entry, catalog_date)


def _mk_store(tmp_path):
    return AlertStore(str(tmp_path / "intel.db"))


def _mk_pipe(store, nvd=None, kev=None):
    return Pipeline(store=store, nvd=nvd or FakeNvd(), kev=kev or FakeKev())


# ---------------------------------------------------------------------------
# deterministic scoring + explanations
# ---------------------------------------------------------------------------


def test_score_rewards_kev_and_is_explainable():
    cvss = CvssMetric(
        version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=9.8,
        base_severity="CRITICAL",
        attack_vector="NETWORK",
        attack_complexity="LOW",
        privileges_required="NONE",
        user_interaction="NONE",
    )
    kev = KevEntry(in_catalog=True, catalog_status="IN_KEV", date_added="2021-12-10")
    v = score_cve(cvss, kev)
    assert v.priority == "CRITICAL"
    assert v.priority_score == 100
    assert v.known_exploited is True
    assert any("CISA KEV" in r for r in v.reasons)
    assert v.thresholds["kev_bump"] == 18


def test_non_kev_medium_stays_not_exploited():
    cvss = CvssMetric(
        version="3.1", vector_string="", base_score=6.5, base_severity="MEDIUM",
        attack_vector="NETWORK", privileges_required="NONE",
        user_interaction="NONE",
    )
    kev = KevEntry(in_catalog=False, catalog_status="NOT_IN_KEV", catalog_date="d")
    v = score_cve(cvss, kev)
    assert v.priority in ("MEDIUM", "HIGH")
    assert v.known_exploited is False
    assert any("suggesting" not in r and "No CVSS" not in r for r in v.reasons)


def test_no_cvss_is_honest_not_invented():
    kev = KevEntry(in_catalog=False, catalog_status="NOT_IN_KEV", catalog_date="d")
    v = score_cve(None, kev)
    assert v.priority == "INFORMATIONAL"
    assert v.priority_score < 20
    assert any("No CVSS metric published" in r for r in v.reasons)


def test_score_is_deterministic_identical_inputs():
    a = score_cve(
        CvssMetric(
            version="3.1", vector_string="", base_score=7.5,
            base_severity="HIGH", attack_vector="NETWORK",
        ),
        KevEntry(in_catalog=True, catalog_status="IN_KEV", date_added="d"),
    )
    b = score_cve(
        CvssMetric(
            version="3.1", vector_string="", base_score=7.5,
            base_severity="HIGH", attack_vector="NETWORK",
        ),
        KevEntry(in_catalog=True, catalog_status="IN_KEV", date_added="d"),
    )
    assert a.priority == b.priority and a.priority_score == b.priority_score
    assert a.reasons == b.reasons


# ---------------------------------------------------------------------------
# NVD parsing
# ---------------------------------------------------------------------------


def test_parse_nvd_sample():
    parsed = parse_cve_json(_NVD_SAMPLE)
    assert parsed["_cve_id"] == "CVE-2021-44228"
    assert parsed["cwes"] == ["CWE-502", "CWE-20"]
    assert parsed["cvss"].base_score == 10.0
    assert parsed["cvss"].base_severity == "CRITICAL"
    assert parsed["affected_products"][0].vendor == "apache"
    assert parsed["affected_products"][0].product == "log4j"
    assert parsed["references"][0]["tags"]
    assert parsed["description"].startswith("Apache Log4j2")


# ---------------------------------------------------------------------------
# CWE -> ATT&CK reasoning
# ---------------------------------------------------------------------------


def test_cwe_to_technique_is_defensible_and_never_random():
    got = attck.techniques_for_cwes(["CWE-502"])
    assert got and got[0]["technique_id"] in ("T1203", "T1210")
    assert "basis" in got[0]
    assert got[0]["technique_name"]

    unknown = attck.techniques_for_cwes(["CWE-999999"])
    assert unknown == []


def test_attck_metadata_is_well_formed():
    got = attck.techniques_for_cwes(["CWE-89"])
    assert got[0]["technique_id"] == "T1190"
    assert got[0]["technique_url"].startswith("https://attack.mitre.org/techniques/T1190")


def test_technique_deduplicated():
    got = attck.techniques_for_cwes(["CWE-89", "CWE-918", "CWE-20"])
    ids = [t["technique_id"] for t in got]
    assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# pipeline: live fetch, cache replay, provenance
# ---------------------------------------------------------------------------


def test_pipeline_live_then_cached(tmp_path, monkeypatch):
    monkeypatch.setenv("CINDER_KEV_TTL_HOURS", "24")
    store = _mk_store(tmp_path)
    nvd = FakeNvd()
    pipe = _mk_pipe(store, nvd=nvd)

    first = pipe.analyze("CVE-2021-44228")
    assert first.data_kind == "live"
    assert first.cvss.base_score == 10.0
    assert first.kev.in_catalog is True
    assert first.kev.catalog_status == "IN_KEV"
    assert first.verdict.priority == "CRITICAL"
    assert first.verdict.known_exploited is True
    assert first.attck[0].technique_id in ("T1203", "T1210")
    assert first.metrics.sources_consulted
    assert nvd.calls == 1

    second = pipe.analyze("CVE-2021-44228")
    assert second.data_kind == "cached"
    assert second.metrics.cached_note and "cache" in second.metrics.cached_note.lower()
    assert nvd.calls == 1  # no second network call


def test_pipeline_force_refetch(tmp_path):
    store = _mk_store(tmp_path)
    nvd = FakeNvd()
    pipe = _mk_pipe(store, nvd=nvd)
    pipe.analyze("CVE-2021-44228")
    pipe.analyze("CVE-2021-44228", force=True)
    assert nvd.calls == 2


def test_pipeline_fallback_to_cache_on_outage(tmp_path, monkeypatch):
    monkeypatch.setenv("CINDER_CACHE_TTL_HOURS", "0")
    store = _mk_store(tmp_path)
    nvd = FakeNvd()
    pipe = _mk_pipe(store, nvd=nvd)
    pipe.analyze("CVE-2021-44228")

    pipe.nvd = FakeNvd(raise_on=["CVE-2021-44228"])
    finding = pipe.analyze("CVE-2021-44228")
    assert finding.data_kind == "cached"
    assert "failed" in finding.metrics.cached_note


def test_pipeline_no_cache_on_outage_raises(tmp_path):
    store = _mk_store(tmp_path)
    pipe = _mk_pipe(store, nvd=FakeNvd(raise_on=["CVE-2021-44228"]))
    with pytest.raises(Exception):
        pipe.analyze("CVE-2021-44228")


def test_search_marks_kev(tmp_path):
    store = _mk_store(tmp_path)
    pipe = _mk_pipe(store)
    results = pipe.search("log4j")
    assert results and results[0].cve_id == "CVE-2021-44228"
    assert results[0].kev_status == "IN_KEV"


def test_stats_are_real_counts(tmp_path):
    store = _mk_store(tmp_path)
    pipe = _mk_pipe(store)
    pipe.analyze("CVE-2021-44228")
    s = pipe.stats()
    assert s.processed == 1
    assert s.priority_distribution == {"CRITICAL": 1}
    assert s.known_exploited == 1
    assert s.kev_catalog_date == "2024.05.01"


# ---------------------------------------------------------------------------
# AI report: never invents, honest fallback
# ---------------------------------------------------------------------------


def test_mock_cve_report_is_deterministic_and_honest():
    p = MockProvider()
    rep = p.cve_report(json.dumps({"cve_id": "CVE-X"}), '{"priority": "LOW"}')
    assert rep.explanation
    assert "not evidence of an intrusion" in rep.explanation
    assert rep.investigation and rep.remediation


def test_mock_cve_report_flags_kev():
    p = MockProvider()
    rep = p.cve_report(
        json.dumps({}),
        '{"priority": "CRITICAL", "known_exploited": true}',
    )
    assert "exploited in the wild" in rep.explanation


def test_finding_model_roundtrip():
    parsed = parse_cve_json(_NVD_SAMPLE)
    v = score_cve(
        parsed["cvss"],
        KevEntry(in_catalog=True, catalog_status="IN_KEV"),
    )
    finding = IntelFinding(
        cve_id="CVE-2021-44228",
        data_kind="live",
        retrieved_at=datetime.now(timezone.utc),
        cvss=parsed["cvss"],
        verdict=v,
        metrics=IntelMetrics(data_kind="live"),
    )
    data = finding.model_dump()
    assert data["verdict"]["priority"] == "CRITICAL"
    assert data["data_kind"] == "live"


# ---------------------------------------------------------------------------
# inventory awareness: "does this CVE affect OUR environment?"
# ---------------------------------------------------------------------------


def test_match_inventory_no_inventory_never_claims():
    got = match_inventory(
        [
            mock_affected("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", "apache", "log4j"),
        ],
        inventory=[],
    )
    assert got["configured"] is False
    assert got["match_status"] == "NO_INVENTORY"
    assert got["matched_cpes"] == []


def test_match_inventory_hit_is_honest():
    got = match_inventory(
        [
            mock_affected("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", "apache", "log4j"),
            mock_affected("cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*", "apache", "tomcat"),
        ],
        inventory=[("apache", "log4j")],
    )
    assert got["configured"] is True
    assert got["match_status"] == "IN_INVENTORY"
    assert got["matched_cpes"] == ["cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"]
    assert got["matched_products"] == ["apache:log4j"]


def test_match_inventory_configured_but_no_hit():
    got = match_inventory(
        [
            mock_affected("cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*", "apache", "tomcat"),
        ],
        inventory=[("paloaltonetworks", "pan-os")],
    )
    assert got["configured"] is True
    assert got["match_status"] == "NOT_IN_INVENTORY"
    assert got["matched_cpes"] == []


def test_pipeline_propagates_inventory_awareness(tmp_path, monkeypatch):
    monkeypatch.setenv("CINDER_INVENTORY", "apache:log4j")
    store = _mk_store(tmp_path)
    pipe = _mk_pipe(store)
    finding = pipe.analyze("CVE-2021-44228")
    assert finding.inventory is not None
    assert finding.inventory.configured is True
    assert finding.inventory.match_status == "IN_INVENTORY"
    assert "apache:log4j" in finding.inventory.matched_products


def test_pipeline_present_unknown_inventory_when_unconfigured(tmp_path, monkeypatch):
    monkeypatch.delenv("CINDER_INVENTORY", raising=False)
    store = _mk_store(tmp_path)
    pipe = _mk_pipe(store)
    finding = pipe.analyze("CVE-2021-44228")
    assert finding.inventory is not None
    assert finding.inventory.match_status == "NO_INVENTORY"


def mock_affected(cpe, vendor, product):
    from app.schemas.intel import AffectedProduct

    return AffectedProduct(cpe=cpe, vendor=vendor, product=product)


# ---------------------------------------------------------------------------
# real ingestion: /alerts/ingest behavior
# ---------------------------------------------------------------------------


def test_ingest_detects_and_creates_alert(tmp_path):
    store = AlertStore(str(tmp_path / "ingest.db"))
    try:
        alert, kind = ingest_raw_log(
            store,
            raw_log=(
                "Mar 10 23:14:15 srv-web sshd[32010]: Failed password for "
                "invalid user admin from 203.0.113.45 port 59224 ssh2"
            ),
            source="corp-firewall",
            source_ip="203.0.113.45",
        )
        assert kind == "detected"
        assert alert.alert_type.value == "SSH_BRUTE_FORCE"
        assert alert.severity.value == "HIGH"
        assert alert.id.startswith("AL-")
        assert store.get_alert(alert.id) is not None
    finally:
        store.close()


def test_ingest_accepts_explicit_sender_type(tmp_path):
    store = AlertStore(str(tmp_path / "ingest2.db"))
    try:
        alert, kind = ingest_raw_log(
            store,
            raw_log="any raw text, type comes from the sender",
            alert_type="PHISHING",
        )
        assert kind == "explicit"
        assert alert.alert_type.value == "PHISHING"
        assert alert.severity.value == "MEDIUM"
    finally:
        store.close()


def test_ingest_rejects_unrecognized_pattern(tmp_path):
    store = AlertStore(str(tmp_path / "ingest3.db"))
    try:
        n_before = store.count()
        with pytest.raises(ValueError):
            ingest_raw_log(store, raw_log="qwerty jibberish no known pattern here")
        assert store.count() == n_before
    finally:
        store.close()