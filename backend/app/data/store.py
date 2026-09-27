"""SQLite-backed alert store using only the Python standard library."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from ..schemas.alerts import Alert, AlertStatus, AlertSummary, AlertType, Severity
from ..schemas.audit import AuditEntry
from .seed_alerts import seed_alerts
from .seed_audit import seed_audit

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    source      TEXT NOT NULL,
    source_ip   TEXT NOT NULL,
    destination TEXT NOT NULL,
    alert_type  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    status      TEXT NOT NULL,
    raw_log     TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id            TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL,
    op            TEXT NOT NULL,
    alert_id      TEXT,
    question      TEXT,
    analysis_mode TEXT NOT NULL,
    model_used    TEXT,
    latency_ms    INTEGER NOT NULL DEFAULT 0,
    severity      TEXT,
    confidence    INTEGER,
    threat_type   TEXT,
    summary       TEXT,
    answer        TEXT,
    overview      TEXT,
    actions_count INTEGER,
    report_len    INTEGER,
    raw_log       TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intel_cve_cache (
    cve_id        TEXT PRIMARY KEY,
    raw_record    TEXT NOT NULL,
    retrieved_at  TEXT NOT NULL,
    last_checked  TEXT NOT NULL,
    verdict       TEXT,
    attck         TEXT,
    kev_entry     TEXT,
    kev_catalog_date TEXT,
    report        TEXT
);

CREATE TABLE IF NOT EXISTS intel_kev_catalog (
    cve_id        TEXT PRIMARY KEY,
    entry_json    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intel_kev_meta (
    key           TEXT PRIMARY KEY,
    value         TEXT NOT NULL
);
"""


class AlertStore:
    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()
        return int(row["n"]) if row else 0

    def ensure_seeded(self) -> None:
        if self.count() == 0:
            self.replace_all(seed_alerts())

    def replace_all(self, alerts: list[Alert]) -> None:
        self._conn.execute("DELETE FROM alerts")
        for a in alerts:
            self._conn.execute(
                "INSERT OR REPLACE INTO alerts "
                "(id, timestamp, source, source_ip, destination, alert_type, "
                " severity, status, raw_log, description) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    a.id,
                    a.timestamp.isoformat(),
                    a.source,
                    a.source_ip,
                    a.destination,
                    a.alert_type.value,
                    a.severity.value,
                    a.status.value,
                    a.raw_log,
                    a.description,
                ),
            )
        self._conn.commit()

    def list_alerts(
        self,
        severity: Severity | None = None,
        status: AlertStatus | None = None,
    ) -> list[AlertSummary]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[str] = []
        if severity:
            query += " AND severity = ?"
            params.append(severity.value)
        if status:
            query += " AND status = ?"
            params.append(status.value)
        query += " ORDER BY timestamp DESC"
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_summary(r) for r in rows]

    def get_alert(self, alert_id: str) -> Alert | None:
        row = self._conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        return self._row_to_alert(row) if row else None

    def update_status(self, alert_id: str, status: AlertStatus) -> Alert | None:
        self._conn.execute(
            "UPDATE alerts SET status = ? WHERE id = ?",
            (status.value, alert_id),
        )
        self._conn.commit()
        return self.get_alert(alert_id)

    def next_id(self) -> str:
        rows = self._conn.execute("SELECT id FROM alerts").fetchall()
        max_seq = 0
        for r in rows:
            try:
                seq = int(str(r["id"]).rsplit("-", 1)[-1])
                max_seq = max(max_seq, seq)
            except ValueError:
                continue
        return f"AL-2024-{max_seq + 1:04d}"

    def create_alert(self, alert: Alert) -> Alert:
        self._conn.execute(
            "INSERT INTO alerts "
            "(id, timestamp, source, source_ip, destination, alert_type, "
            " severity, status, raw_log, description) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                alert.id,
                alert.timestamp.isoformat(),
                alert.source,
                alert.source_ip,
                alert.destination,
                alert.alert_type.value,
                alert.severity.value,
                alert.status.value,
                alert.raw_log,
                alert.description,
            ),
        )
        self._conn.commit()
        return alert

    def stats(self) -> dict[str, int]:
        by_severity = dict(
            self._conn.execute(
                "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
            ).fetchall()
        )
        by_status = dict(
            self._conn.execute(
                "SELECT status, COUNT(*) FROM alerts GROUP BY status"
            ).fetchall()
        )
        by_type = dict(
            self._conn.execute(
                "SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type"
            ).fetchall()
        )
        total = int(
            self._conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
        )
        return {
            "total": total,
            "critical": by_severity.get("CRITICAL", 0),
            "high": by_severity.get("HIGH", 0),
            "medium": by_severity.get("MEDIUM", 0),
            "low": by_severity.get("LOW", 0),
            "by_severity": by_severity,
            "by_status": by_status,
            "by_type": by_type,
        }

    @staticmethod
    def _row_to_summary(row: sqlite3.Row) -> AlertSummary:
        return AlertSummary(
            id=row["id"],
            timestamp=row["timestamp"],
            source=row["source"],
            source_ip=row["source_ip"],
            destination=row["destination"],
            alert_type=AlertType(row["alert_type"]),
            severity=Severity(row["severity"]),
            status=AlertStatus(row["status"]),
        )

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> Alert:
        return Alert(
            id=row["id"],
            timestamp=row["timestamp"],
            source=row["source"],
            source_ip=row["source_ip"],
            destination=row["destination"],
            alert_type=AlertType(row["alert_type"]),
            severity=Severity(row["severity"]),
            status=AlertStatus(row["status"]),
            raw_log=row["raw_log"],
            description=row["description"],
        )

    def audit_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM audit_log").fetchone()
        return int(row["n"]) if row else 0

    def ensure_audit_seeded(self) -> None:
        if self.audit_count() == 0:
            self.replace_audit(seed_audit())

    def replace_audit(self, entries: list[AuditEntry]) -> None:
        self._conn.execute("DELETE FROM audit_log")
        for e in entries:
            self._conn.execute(
                "INSERT OR REPLACE INTO audit_log "
                "(id, session_id, op, alert_id, question, analysis_mode, model_used, "
                " latency_ms, severity, confidence, threat_type, summary, answer, "
                " overview, actions_count, report_len, raw_log, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    e.id,
                    e.session_id,
                    e.op,
                    e.alert_id,
                    e.question,
                    e.analysis_mode,
                    e.model_used,
                    e.latency_ms,
                    e.severity,
                    e.confidence,
                    e.threat_type,
                    e.summary,
                    e.answer,
                    e.overview,
                    e.actions_count,
                    e.report_len,
                    e.raw_log,
                    e.created_at.isoformat(),
                ),
            )
        self._conn.commit()

    def insert_audit(self, entry: AuditEntry) -> None:
        self._conn.execute(
            "INSERT INTO audit_log "
            "(id, session_id, op, alert_id, question, analysis_mode, model_used, "
            " latency_ms, severity, confidence, threat_type, summary, answer, "
            " overview, actions_count, report_len, raw_log, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                entry.id,
                entry.session_id,
                entry.op,
                entry.alert_id,
                entry.question,
                entry.analysis_mode,
                entry.model_used,
                entry.latency_ms,
                entry.severity,
                entry.confidence,
                entry.threat_type,
                entry.summary,
                entry.answer,
                entry.overview,
                entry.actions_count,
                entry.report_len,
                entry.raw_log,
                entry.created_at.isoformat(),
            ),
        )
        self._conn.commit()

    def list_audit(self) -> list[AuditEntry]:
        rows = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY created_at ASC"
        ).fetchall()
        return [self._row_to_audit(r) for r in rows]

    @staticmethod
    def _row_to_audit(row: sqlite3.Row) -> AuditEntry:
        from datetime import datetime

        return AuditEntry(
            id=row["id"],
            session_id=row["session_id"],
            op=row["op"],
            alert_id=row["alert_id"],
            question=row["question"],
            analysis_mode=row["analysis_mode"],
            model_used=row["model_used"],
            latency_ms=row["latency_ms"] or 0,
            severity=row["severity"],
            confidence=row["confidence"],
            threat_type=row["threat_type"],
            summary=row["summary"],
            answer=row["answer"],
            overview=row["overview"],
            actions_count=row["actions_count"],
            report_len=row["report_len"],
            raw_log=row["raw_log"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def close(self) -> None:
        self._conn.close()

    # --- Intel (CVE intelligence) cache -------------------------------------

    def intel_get_cve(self, cve_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM intel_cve_cache WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if not row:
            return None
        return {
            "cve_id": row["cve_id"],
            "raw_record": row["raw_record"],
            "retrieved_at": row["retrieved_at"],
            "last_checked": row["last_checked"],
            "verdict": row["verdict"],
            "attck": row["attck"],
            "kev_entry": row["kev_entry"],
            "kev_catalog_date": row["kev_catalog_date"],
            "report": row["report"],
        }

    def intel_put_cve(
        self,
        cve_id: str,
        raw_record: str,
        retrieved_at: str,
        last_checked: str,
        verdict: str | None = None,
        attck: str | None = None,
        kev_entry: str | None = None,
        kev_catalog_date: str | None = None,
        report: str | None = None,
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO intel_cve_cache "
            "(cve_id, raw_record, retrieved_at, last_checked, verdict, attck, "
            " kev_entry, kev_catalog_date, report) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                cve_id,
                raw_record,
                retrieved_at,
                last_checked,
                verdict,
                attck,
                kev_entry,
                kev_catalog_date,
                report,
            ),
        )
        self._conn.commit()

    def intel_introspect_fresh(self, cve_id: str, max_age_days: float) -> bool:
        """True when a cached CVE record is fresh enough to skip a live fetch."""
        row = self._conn.execute(
            "SELECT last_checked FROM intel_cve_cache WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if not row:
            return False
        from datetime import datetime, timezone

        try:
            checked = datetime.fromisoformat(row["last_checked"])
        except ValueError:
            return False
        return (datetime.now(timezone.utc) - checked).total_seconds() < (
            max_age_days * 86400
        )

    def intel_cve_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM intel_cve_cache").fetchone()
        return int(row["n"]) if row else 0

    def intel_cves(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM intel_cve_cache ORDER BY retrieved_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def intel_kev_get_released(self) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM intel_kev_meta WHERE key = 'dateReleased'"
        ).fetchone()
        return row["value"] if row else None

    def intel_kev_replace(self, entries: dict[str, dict], date_released: str | None) -> None:
        self._conn.execute("DELETE FROM intel_kev_catalog")
        for cve_id, entry in entries.items():
            self._conn.execute(
                "INSERT OR REPLACE INTO intel_kev_catalog (cve_id, entry_json) "
                "VALUES (?,?)",
                (cve_id, json.dumps(entry)),
            )
        self._conn.execute(
            "INSERT OR REPLACE INTO intel_kev_meta (key, value) VALUES ('dateReleased', ?)",
            (date_released or "",),
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO intel_kev_meta (key, value) VALUES "
            "('lastFetched', ?)",
            (datetime.now(timezone.utc).isoformat(),),
        )
        self._conn.commit()

    def intel_kev_get_entry(self, cve_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT entry_json FROM intel_kev_catalog WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["entry_json"])
        except (json.JSONDecodeError, TypeError):
            return None

    def intel_kev_last_fetched(self) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM intel_kev_meta WHERE key = 'lastFetched'"
        ).fetchone()
        return row["value"] if row else None