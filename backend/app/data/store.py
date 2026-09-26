"""SQLite-backed alert store using only the Python standard library."""

import sqlite3
from pathlib import Path

from ..schemas.alerts import Alert, AlertStatus, AlertSummary, AlertType, Severity
from .seed_alerts import seed_alerts

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

    def close(self) -> None:
        self._conn.close()