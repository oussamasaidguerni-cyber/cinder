"""Tests for the Auditor's hidden-failure detection (SupplyzPro challenge).

These assert the entire demo contract: the seeded synthetic trail produces the
five signature failure classes, grouped and ranked, with recoveries and
ambiguous cases separated from real failures, and no false positives on the
clean sessions.
"""

from app.data.seed_audit import seed_audit
from app.data.store import AlertStore
from app.services.audit import build_trail


def _seeded_trail(tmp_path):
    path = tmp_path / "audit.db"
    store = AlertStore(path)
    store.replace_audit(seed_audit())
    store.close()
    return build_trail(ai_pass=False, db_path=str(path))


def test_trail_has_all_pieces(tmp_path):
    trail = _seeded_trail(tmp_path)
    assert trail.entry_count == 15
    assert len(trail.groups) == 5  # one problem group per signature
    assert len(trail.recoveries) == 1  # the failed-then-recovered session
    assert len(trail.ambiguous) == 1  # the legit re-ask case


def test_all_five_signatures_detected(tmp_path):
    trail = _seeded_trail(tmp_path)
    signatures = {f.signature for f in trail.findings}
    assert signatures == {
        "unsupported_success_claim",
        "repeated_questions",
        "no_progress_search",
        "wrong_record",
        "incomplete_finished",
    }


def test_clean_sessions_are_not_flagged(tmp_path):
    trail = _seeded_trail(tmp_path)
    clean = {"run-analyze-0001", "run-analyze-0002", "run-correlate-0003"}
    for f in trail.findings:
        assert not (clean & set(f.entry_ids)), f"clean run flagged: {f.signature}"


def test_recovery_not_counted_as_failure(tmp_path):
    trail = _seeded_trail(tmp_path)
    # session sess-rec-001 is a recovery, its entries must not appear in findings
    involved = {e for f in trail.findings for e in f.entry_ids}
    assert not ({"run-analyze-0004", "run-analyze-0005"} & involved)
    assert any(r.session_id == "sess-rec-001" for r in trail.recoveries)


def test_wrong_record_cites_foreign_ip(tmp_path):
    trail = _seeded_trail(tmp_path)
    wrong = next(f for f in trail.findings if f.signature == "wrong_record")
    assert wrong.severity == "HIGH"
    assert any("198.51.100.77" in e for e in wrong.evidence)
    # the grounding line proves the answer referenced a record never present
    assert any("grounding" in e for e in wrong.evidence)


def test_no_progress_flagged_high(tmp_path):
    trail = _seeded_trail(tmp_path)
    nog = [f for f in trail.findings if f.signature == "no_progress_search"]
    assert len(nog) == 2  # two consecutive dead-end pairs
    assert all(f.severity == "HIGH" for f in nog)
    assert nog[0].session_id == "sess-ask-002"


def test_ranking_groups_sorted_by_score(tmp_path):
    trail = _seeded_trail(tmp_path)
    scores = [g.score for g in trail.groups]
    assert scores == sorted(scores, reverse=True)
    assert trail.groups[0].signature == "no_progress_search"


def test_honesty_panel(tmp_path):
    trail = _seeded_trail(tmp_path)
    assert trail.runtime_ms >= 0
    assert trail.cost_note.startswith("$0.00")
    assert len(trail.limitations) >= 3
    assert trail.ai_insights == []  # deterministic mode makes no LLM calls


def test_unsupported_claim_needs_engine_contradiction(tmp_path):
    trail = _seeded_trail(tmp_path)
    claim = next(f for f in trail.findings if f.signature == "unsupported_success_claim")
    assert claim.severity == "HIGH"
    assert "engine" in claim.explanation or "verdict" in claim.explanation