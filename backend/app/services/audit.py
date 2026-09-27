"""The Auditor: find hidden failures in CINDER's agent-run trail.

An AI agent can finish without a technical error and still fail the user
(SupplyzPro "Find the Hidden Failures" challenge). CINDER records every agent
operation as an AuditEntry; this module scans those transcripts for the five
signature failure classes, groups related cases into sessions, and returns a
ranked, evidence-backed issue list — while distinguishing real failures from
legitimate retries and honest recoveries.

Detection is deliberately deterministic (fast, auditable, $0, works offline).
An OPTIONAL AI pass (ai_pass=True) adds a narrated "fix this first" take for the
top groups using the configured provider; it soft-fails to deterministic text.
"""

import re
import time
from datetime import datetime, timezone
from difflib import SequenceMatcher

from ..ai.provider import AIError, get_provider
from ..data.store import AlertStore
from ..schemas.audit import (
    CHALLENGE_LABELS,
    SEVERITY_WEIGHT,
    AuditEntry,
    AuditFinding,
    AuditGroup,
    AuditInsight,
    AuditRecovery,
    AuditTrailResponse,
)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b[A-Z]{2,6}-\d{2,3}\b")

# Words that assert a success or a confirmed outcome the agent may not deserve.
_CLAIM_WORDS = [
    "confirmed",
    "contained",
    "neutralized",
    "blocked",
    "stopped",
    "eliminated",
    "verified",
    "100%",
    "remediated",
    "secured",
    "fully removed",
]

_CLEAN_LABEL = "No hidden failures detected in audited runs."

_LIMITATIONS = [
    "Signature checks are heuristics: claim-word matching can miss hedged or "
    "sarcastic language that still oversells a result.",
    "'Same question' detection uses normalized text similarity (not embeddings); "
    "heavy rephrasiings of the same intent may be missed, short paraphrases may "
    "overlap.",
    "Evidence snippets are truncated to keep the trail light; a full finding may "
    "need the raw transcript rows.",
    "Detects unsupported claims and missing artifacts, not silent semantic "
    "drift (answers that are technically complete but simply wrong).",
    "A live-model outage surfaces as an honest fallback+recovery, which the "
    "auditor deliberately does NOT count as a hidden failure.",
    "Dead-end answers that ARE the intended deterministic behavior get flagged "
    "only when they repeat and burn analyst time.",
]

_SIG_SEVERITY: dict[str, str] = {
    "unsupported_success_claim": "HIGH",
    "repeated_questions": "MEDIUM",
    "no_progress_search": "HIGH",
    "wrong_record": "HIGH",
    "incomplete_finished": "MEDIUM",
}

_find_seq = [0]


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9 ]+", " ", text.lower()).strip()


def _ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, _norm(a), _norm(b)).ratio()


def _ips(text: str) -> set[str]:
    return set(_IP_RE.findall(text))


def _hosts(text: str) -> set[str]:
    return set(_HOST_RE.findall(text))


def _sentence_of(text: str, word: str) -> str:
    for sent in re.split(r"(?<=[.!?])\s+", text):
        if word in sent.lower():
            return sent.strip()
    return text.strip()[:200]


def _next_finding_id() -> str:
    _find_seq[0] += 1
    return f"fnd-{_find_seq[0]:04d}"


# --------------------------------------------------------------------------- #
# Failure-signature checks. Each returns (finding | None, [ambiguous candidates]).
# --------------------------------------------------------------------------- #


def _check_unsupported_claim(entries: list[AuditEntry]) -> tuple[list[AuditFinding], list[AuditFinding]]:
    findings: list[AuditFinding] = []
    for e in entries:
        if e.analysis_mode != "ai" or not e.summary:
            continue
        norm_summary = _norm(e.summary)
        hits = [w for w in _CLAIM_WORDS if w in norm_summary]
        if not hits:
            continue
        sev = (e.severity or "").upper()
        engine_conf = e.confidence if e.confidence is not None else 50
        h_word = hits[0]
        evidence = [
            f"{e.op.upper()} {e.id} ({e.created_at.strftime('%H:%M')}): "
            f'"{_sentence_of(e.summary, h_word)}"',
            f"engine verdict behind this run: severity {sev}, confidence {engine_conf}%",
        ]
        if sev == "LOW" or engine_conf < 60:
            findings.append(
                AuditFinding(
                    id=_next_finding_id(),
                    signature="unsupported_success_claim",
                    label=CHALLENGE_LABELS["unsupported_success_claim"],
                    severity="HIGH",
                    confidence=0.85,
                    session_id=e.session_id,
                    entry_ids=[e.id],
                    evidence=evidence,
                    explanation=(
                        f"The narrative claims '{h_word}' while the engine's own "
                        f"verdict for this run was only {sev} severity at "
                        f"{engine_conf}% confidence — an unsupported success claim."
                    ),
                )
            )
        elif sev == "MEDIUM" and engine_conf < 70:
            findings.append(
                AuditFinding(
                    id=_next_finding_id(),
                    signature="unsupported_success_claim",
                    label=CHALLENGE_LABELS["unsupported_success_claim"],
                    severity="MEDIUM",
                    confidence=0.5,
                    session_id=e.session_id,
                    entry_ids=[e.id],
                    evidence=evidence,
                    explanation=(
                        f"Narrative uses the strong word '{h_word}' but the engine "
                        f"only reached {sev} at {engine_conf}% confidence."
                    ),
                )
            )
    return findings, []


def _check_repeated_questions(entries: list[AuditEntry]) -> tuple[list[AuditFinding], list[AuditFinding]]:
    asks = [e for e in entries if e.op == "ask" and e.question and e.answer]
    findings: list[AuditFinding] = []
    ambiguous: list[AuditFinding] = []
    groups_by_session: dict[str, list[list[AuditEntry]]] = {}
    for e in asks:
        placed = False
        for bucket in groups_by_session.setdefault(e.session_id, []):
            if _ratio(bucket[0].question or "", e.question or "") >= 0.85:
                bucket.append(e)
                placed = True
                break
        if not placed:
            groups_by_session.setdefault(e.session_id, []).append([e])
    for session_id, buckets in groups_by_session.items():
        for bucket in buckets:
            if len(bucket) < 2:
                continue
            first, last = bucket[0], bucket[-1]
            same_answer = _ratio(first.answer or "", last.answer or "") >= 0.8
            evidence = [
                f"{e.op.upper()} {e.id} ({e.created_at.strftime('%H:%M')}): "
                f'Q: "{e.question}" → A: "{e.answer[:180]}"'
                for e in bucket
            ]
            if same_answer:
                findings.append(
                    AuditFinding(
                        id=_next_finding_id(),
                        signature="repeated_questions",
                        label=CHALLENGE_LABELS["repeated_questions"],
                        severity="HIGH" if len(bucket) >= 3 else "MEDIUM",
                        confidence=0.9,
                        session_id=session_id,
                        entry_ids=[e.id for e in bucket],
                        evidence=evidence,
                        explanation=(
                            f"The same question was asked {len(bucket)}x and the "
                            f"agent returned the same answer each time — the first "
                            f"response did not land, and the loop made no progress."
                        ),
                    )
                )
            else:
                ambiguous.append(
                    AuditFinding(
                        id=_next_finding_id(),
                        signature="repeated_questions",
                        label=CHALLENGE_LABELS["repeated_questions"],
                        severity="LOW",
                        confidence=0.45,
                        session_id=session_id,
                        entry_ids=[e.id for e in bucket],
                        evidence=evidence,
                        explanation=(
                            "The question was re-asked but the answer changed "
                            "materially — likely a legitimate re-ask after new "
                            "context, not a failure. Kept for human review."
                        ),
                    )
                )
    return findings, ambiguous


def _check_no_progress(entries: list[AuditEntry]) -> tuple[list[AuditFinding], list[AuditFinding]]:
    asks = sorted(
        [e for e in entries if e.op == "ask" and e.answer],
        key=lambda e: e.created_at,
    )
    findings: list[AuditFinding] = []
    any_pair = False
    for i in range(len(asks) - 1):
        a, b = asks[i], asks[i + 1]
        if _ratio(a.answer or "", b.answer or "") >= 0.9 and _ratio(
            a.question or "", b.question or ""
        ) < 0.7:
            any_pair = True
            finding = AuditFinding(
                id=_next_finding_id(),
                signature="no_progress_search",
                label=CHALLENGE_LABELS["no_progress_search"],
                severity="MEDIUM",
                confidence=0.62,
                session_id=a.session_id,
                entry_ids=[a.id, b.id],
                evidence=[
                    f"Q{i+1}: \"{x.question}\" → A: \"{x.answer[:180]}\""
                    for i, x in enumerate((a, b))
                ],
                explanation=(
                    "Two different questions produced near-identical answers: "
                    "the search is not progressing, it is re-serving the same "
                    "result."
                ),
            )
            findings.append(finding)
            if len(asks) >= 3 and _ratio(a.answer or "", asks[0].answer or "") >= 0.9:
                finding.severity = "HIGH"
                finding.confidence = 0.85
                finding.explanation = (
                    "Three or more distinct probes all returned the same dead-end "
                    "answer — the agent burned several analyst turns without "
                    "progress."
                )
    return findings, []


def _check_wrong_record(entries: list[AuditEntry]) -> tuple[list[AuditFinding], list[AuditFinding]]:
    findings: list[AuditFinding] = []
    for e in entries:
        narrative = (e.summary or e.answer or e.overview or "").strip()
        if not narrative or not e.raw_log:
            continue
        narr_ips = _ips(narrative)
        ground_ips = _ips(e.raw_log)
        stray_ips = narr_ips - ground_ips
        narr_hosts = _hosts(narrative)
        ground_hosts = _hosts(e.raw_log)
        stray_hosts = narr_hosts - ground_hosts
        # Only call a host stray if the grounding actually names hosts.
        stray_hosts = stray_hosts if ground_hosts else set()
        if not stray_ips and not stray_hosts:
            continue
        det = list(stray_ips) + list(stray_hosts)
        findings.append(
            AuditFinding(
                id=_next_finding_id(),
                signature="wrong_record",
                label=CHALLENGE_LABELS["wrong_record"],
                severity="HIGH",
                confidence=0.85 if len(det) == 1 else 0.92,
                session_id=e.session_id,
                entry_ids=[e.id],
                evidence=[
                    f"{e.op.upper()} {e.id} artifact: \"{narrative[:220]}\"",
                    f"grounding text contained only: {sorted(ground_ips)} {sorted(ground_hosts)}",
                ],
                explanation=(
                    "The agent's narrative references {" + ", ".join(sorted(det))
                    + "} that never appear in the grounding text it was supposed to "
                    "be built from — a wrong/foreign record presented as the answer."
                ),
            )
        )
    return findings, []


def _check_incomplete(entries: list[AuditEntry]) -> tuple[list[AuditFinding], list[AuditFinding]]:
    findings: list[AuditFinding] = []
    for e in entries:
        if e.op == "analyze" and e.analysis_mode == "ai":
            if e.actions_count is not None and e.actions_count == 0 and (e.severity or "LOW").upper() not in ("LOW", "NONE"):
                findings.append(
                    AuditFinding(
                        id=_next_finding_id(),
                        signature="incomplete_finished",
                        label=CHALLENGE_LABELS["incomplete_finished"],
                        severity="MEDIUM",
                        confidence=0.7,
                        session_id=e.session_id,
                        entry_ids=[e.id],
                        evidence=[
                            f"{e.op.upper()} {e.id} returned recommended_actions: 0",
                            f'summary: "{e.summary[:160]}"' if e.summary else f"op {e.id}",
                        ],
                        explanation=(
                            "A non-trivial alert analysis was returned as finished "
                            "with ZERO recommended actions — the analyst has "
                            "nothing actionable to do next."
                        ),
                    )
                )
            if e.report_len == 0 and (e.severity or "").upper() in ("HIGH", "CRITICAL"):
                findings.append(
                    AuditFinding(
                        id=_next_finding_id(),
                        signature="incomplete_finished",
                        label=CHALLENGE_LABELS["incomplete_finished"],
                        severity="MEDIUM",
                        confidence=0.55,
                        session_id=e.session_id,
                        entry_ids=[e.id],
                        evidence=[
                            f"{e.op.upper()} {e.id} incident_report length: 0",
                            f'summary: "{e.summary[:160]}"' if e.summary else f"op {e.id}",
                        ],
                        explanation=(
                            "A high/critical finding shipped without an incident "
                            "report — incomplete work presented as finished."
                        ),
                    )
                )
        elif e.op == "correlate" and e.actions_count == 0:
            findings.append(
                AuditFinding(
                    id=_next_finding_id(),
                    signature="incomplete_finished",
                    label=CHALLENGE_LABELS["incomplete_finished"],
                    severity="MEDIUM",
                    confidence=0.75,
                    session_id=e.session_id,
                    entry_ids=[e.id],
                    evidence=[
                        f"CORRELATE {e.id} returned recommended_actions: 0",
                        f'overview: "{e.overview[:160]}"' if e.overview else f"op {e.id}",
                    ],
                    explanation=(
                        "The correlation run completed with an overview but no "
                        "recommended actions — a hunt handed to the analyst "
                        "without a next step."
                    ),
                )
            )
    return findings, []


# --------------------------------------------------------------------------- #
# Orchestration.
# --------------------------------------------------------------------------- #


def _next_finding_id() -> str:
    _find_seq[0] += 1
    return f"fnd-{_find_seq[0]:04d}"


def _detect_failures(entries: list[AuditEntry]) -> tuple[list[AuditFinding], list[AuditFinding], list[AuditRecovery]]:
    findings: list[AuditFinding] = []
    ambiguous: list[AuditFinding] = []

    by_session: dict[str, list[AuditEntry]] = {}
    for e in entries:
        by_session.setdefault(e.session_id, []).append(e)
    for check in (
        _check_unsupported_claim,
        _check_repeated_questions,
        _check_no_progress,
        _check_wrong_record,
        _check_incomplete,
    ):
        for session_entries in by_session.values():
            f, a = check(session_entries)
            findings.extend(f)
            ambiguous.extend(a)
    return findings, ambiguous, _detect_recoveries(entries)


def _detect_recoveries(entries: list[AuditEntry]) -> list[AuditRecovery]:
    recoveries: list[AuditRecovery] = []
    by_sess_alert: dict[tuple[str, str | None, str], list[AuditEntry]] = {}
    for e in entries:
        by_sess_alert.setdefault((e.session_id, e.alert_id, e.op), []).append(e)
    for (session_id, _aid, op), grouped in by_sess_alert.items():
        sorted_ = sorted(grouped, key=lambda e: e.created_at)
        for i in range(len(sorted_) - 1):
            first, later = sorted_[i], sorted_[i + 1]
            if first.analysis_mode == "fallback" and later.analysis_mode == "ai":
                text_f = first.summary or first.answer or ""
                text_l = later.summary or later.answer or ""
                if text_f and text_l and _ratio(text_f, text_l) < 0.75:
                    recoveries.append(
                        AuditRecovery(
                            session_id=session_id,
                            label="AI call failed then recovered on retry",
                            entry_ids=[first.id, later.id],
                            evidence=[
                                f"{op.upper()} {first.id} (fallback): "
                                f'"{text_f[:180]}"',
                                f"{op.upper()} {later.id} (live AI): "
                                f'"{text_l[:180]}"',
                            ],
                        )
                    )
    return recoveries


def _group_and_rank(findings: list[AuditFinding]) -> list[AuditGroup]:
    by_sig: dict[str, list[AuditFinding]] = {}
    for f in findings:
        by_sig.setdefault(f.signature, []).append(f)
    groups: list[AuditGroup] = []
    for signature, members in by_sig.items():
        weight = SEVERITY_WEIGHT.get(_SIG_SEVERITY.get(signature, "MEDIUM"), 2)
        avg_conf = sum(m.confidence for m in members) / len(members)
        count = sum(len(m.entry_ids) for m in members)
        sessions = sorted({m.session_id for m in members})
        score = weight * len(members) * avg_conf
        groups.append(
            AuditGroup(
                signature=signature,
                label=CHALLENGE_LABELS.get(signature, signature),
                severity=_SIG_SEVERITY.get(signature, "MEDIUM"),
                count=count,
                sessions=sessions,
                score=round(score, 2),
            )
        )
    groups.sort(key=lambda g: g.score, reverse=True)
    return groups


def _ai_insights(groups: list[AuditGroup]) -> tuple[list[AuditInsight], int, str]:
    provider = get_provider()
    if not provider.is_live() or not groups:
        return [], 0, "no live AI configured"
    insights: list[AuditInsight] = []
    for g in groups[:3]:
        facts = "\n".join(
            [
                f"{g.label} (signature {g.signature}) recurs {g.count} times across "
                f"sessions {', '.join(g.sessions)}.",
            ]
        )
        try:
            text = provider.audit_insight(facts)
        except AIError:
            text = (
                "AI insight unavailable; rerun with the deterministic notes. "
                f"Top problem {g.label} is the highest-scored group — reproduce "
                "one quoted session first."
            )
        insights.append(AuditInsight(signature=g.signature, label=g.label, insight=text))
    return insights, len(insights), provider.model_name


def record_run(entry: AuditEntry, db_path: str | None = None) -> None:
    """Append one agent run to the shared audit trail (live ingestion)."""
    store = AlertStore(db_path or "data/cinder.db")
    try:
        store.insert_audit(entry)
    finally:
        store.close()


def build_trail(ai_pass: bool = False, db_path: str | None = None) -> AuditTrailResponse:
    store = AlertStore(db_path or "data/cinder.db")
    try:
        try:
            entries = store.list_audit()
        finally:
            store.close()
    except Exception:
        store.close()
        entries = []

    start = time.perf_counter()
    findings, ambiguous, recoveries = _detect_failures(entries)
    # Rank by severity, then confidence: what to investigate first.
    findings = sorted(
        findings,
        key=lambda f: (
            -SEVERITY_WEIGHT.get(f.severity, 2),
            -f.confidence,
        ),
    )
    runtime_ms = int((time.perf_counter() - start) * 1000)
    groups = _group_and_rank(findings)

    provider = get_provider()
    insights, insight_count, model_name = [], 0, ""
    cost_note = "$0.00 — deterministic detection only, no external calls"
    if ai_pass:
        insights, insight_count, model_name = _ai_insights(groups)
        if insight_count:
            cost_note = (
                f"{insight_count} LLM call(s) to {model_name} (~0.3-0.5K tokens "
                "each, billed to the provider key) + deterministic scan above"
            )

    return AuditTrailResponse(
        generated_at=datetime.now(timezone.utc),
        method="deterministic signature checks (+ optional AI insights)" if ai_pass else "deterministic signature checks",
        ai_provider=provider.name,
        ai_status=(
            f"insights via {model_name}" if ai_pass and insight_count else "deterministic only"
        ),
        entry_count=len(entries),
        findings=findings,
        groups=groups,
        recoveries=recoveries,
        ambiguous=ambiguous,
        ai_insights=insights,
        limitations=_LIMITATIONS,
        runtime_ms=runtime_ms,
        cost_note=cost_note,
    )