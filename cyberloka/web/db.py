"""SQLite-backed persistence for the dashboard."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB_PATH = Path.home() / ".cyberloka" / "dashboard.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    label TEXT,
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    mode TEXT NOT NULL,
    modules_json TEXT NOT NULL,
    status TEXT NOT NULL,
    progress INTEGER NOT NULL DEFAULT 0,
    progress_total INTEGER NOT NULL DEFAULT 0,
    current_module TEXT,
    started_at TEXT,
    finished_at TEXT,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_label TEXT,
    summary_json TEXT,
    error TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    target TEXT,
    evidence TEXT,
    remediation TEXT,
    references_json TEXT,
    cwe TEXT,
    owasp_category TEXT,
    confidence TEXT,
    detected_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);

CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    interval_hours REAL NOT NULL DEFAULT 24,
    mode TEXT NOT NULL DEFAULT 'passive',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run TEXT,
    next_run TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifiers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,           -- webhook | slack | email
    url TEXT,                     -- webhook/slack URL OR mailto:user@example.com
    min_severity TEXT NOT NULL DEFAULT 'high',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
"""

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


class Database:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path or DEFAULT_DB_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = _connect(self.path)
        with self._conn:
            self._conn.executescript(_SCHEMA)

    @contextmanager
    def cursor(self):
        with _lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            finally:
                cur.close()

    # ---- targets ------------------------------------------------------
    def upsert_target(self, url: str, label: str | None = None, notes: str | None = None) -> int:
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO targets (url, label, notes, created_at)
                   VALUES (?,?,?,?)
                   ON CONFLICT(url) DO UPDATE SET
                     label = excluded.label,
                     notes = excluded.notes
                   RETURNING id""",
                (url, label, notes, _now()),
            )
            return cur.fetchone()[0]

    def list_targets(self) -> list[dict]:
        with self.cursor() as cur:
            cur.execute(
                """SELECT t.*,
                   (SELECT COUNT(*) FROM scans s WHERE s.target_id = t.id) AS scan_count,
                   (SELECT MAX(s.finished_at) FROM scans s WHERE s.target_id = t.id) AS last_scan,
                   (SELECT s.risk_score FROM scans s
                      WHERE s.target_id = t.id AND s.status='done'
                      ORDER BY s.finished_at DESC LIMIT 1) AS last_risk_score
                   FROM targets t ORDER BY t.created_at DESC"""
            )
            return [dict(r) for r in cur.fetchall()]

    def get_target(self, target_id: int) -> dict | None:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM targets WHERE id=?", (target_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def delete_target(self, target_id: int) -> None:
        with self.cursor() as cur:
            cur.execute("DELETE FROM targets WHERE id=?", (target_id,))

    # ---- scans --------------------------------------------------------
    def create_scan(
        self,
        target_id: int,
        mode: str,
        modules: list[str],
        progress_total: int,
    ) -> int:
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO scans (target_id, mode, modules_json, status,
                       progress, progress_total, created_at)
                   VALUES (?,?,?,?,?,?,?)
                   RETURNING id""",
                (
                    target_id,
                    mode,
                    json.dumps(modules),
                    "queued",
                    0,
                    progress_total,
                    _now(),
                ),
            )
            return cur.fetchone()[0]

    def update_scan(self, scan_id: int, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        with self.cursor() as cur:
            cur.execute(
                f"UPDATE scans SET {cols} WHERE id=?",
                (*fields.values(), scan_id),
            )

    def list_scans(self, target_id: int | None = None, limit: int = 50) -> list[dict]:
        sql = (
            """SELECT s.*, t.url AS target_url, t.label AS target_label
               FROM scans s JOIN targets t ON t.id = s.target_id"""
        )
        params: tuple = ()
        if target_id is not None:
            sql += " WHERE s.target_id=?"
            params = (target_id,)
        sql += " ORDER BY s.created_at DESC LIMIT ?"
        params = (*params, limit)
        with self.cursor() as cur:
            cur.execute(sql, params)
            return [self._scan_row(dict(r)) for r in cur.fetchall()]

    def list_done_scans_for_target(self, target_id: int, limit: int = 10) -> list[dict]:
        with self.cursor() as cur:
            cur.execute(
                """SELECT * FROM scans WHERE target_id=? AND status='done'
                   ORDER BY finished_at DESC LIMIT ?""",
                (target_id, limit),
            )
            return [self._scan_row(dict(r)) for r in cur.fetchall()]

    def get_scan(self, scan_id: int) -> dict | None:
        with self.cursor() as cur:
            cur.execute(
                """SELECT s.*, t.url AS target_url, t.label AS target_label
                   FROM scans s JOIN targets t ON t.id = s.target_id
                   WHERE s.id=?""",
                (scan_id,),
            )
            row = cur.fetchone()
            return self._scan_row(dict(row)) if row else None

    def delete_scan(self, scan_id: int) -> None:
        with self.cursor() as cur:
            cur.execute("DELETE FROM scans WHERE id=?", (scan_id,))

    @staticmethod
    def _scan_row(row: dict) -> dict:
        try:
            row["modules"] = json.loads(row.get("modules_json") or "[]")
        except json.JSONDecodeError:
            row["modules"] = []
        try:
            row["summary"] = json.loads(row.get("summary_json") or "null")
        except json.JSONDecodeError:
            row["summary"] = None
        return row

    # ---- findings -----------------------------------------------------
    def insert_findings(self, scan_id: int, findings: list[dict]) -> None:
        rows = []
        for f in findings:
            rows.append(
                (
                    scan_id,
                    f.get("module"),
                    f.get("title"),
                    f.get("severity"),
                    f.get("risk_score") or 0,
                    f.get("description"),
                    f.get("target"),
                    f.get("evidence"),
                    f.get("remediation"),
                    json.dumps(f.get("references") or []),
                    f.get("cwe"),
                    f.get("owasp_category"),
                    f.get("confidence"),
                    f.get("detected_at"),
                )
            )
        with self.cursor() as cur:
            cur.executemany(
                """INSERT INTO findings
                   (scan_id, module, title, severity, risk_score, description,
                    target, evidence, remediation, references_json, cwe,
                    owasp_category, confidence, detected_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )

    def list_findings(self, scan_id: int) -> list[dict]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM findings WHERE scan_id=? ORDER BY "
                "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, module",
                (scan_id,),
            )
            out = []
            for row in cur.fetchall():
                d = dict(row)
                try:
                    d["references"] = json.loads(d.pop("references_json") or "[]")
                except json.JSONDecodeError:
                    d["references"] = []
                out.append(d)
            return out

    def get_finding(self, finding_id: int) -> dict | None:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM findings WHERE id=?", (finding_id,))
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            try:
                d["references"] = json.loads(d.pop("references_json") or "[]")
            except json.JSONDecodeError:
                d["references"] = []
            return d

    # ---- schedules ----------------------------------------------------
    def create_schedule(self, target_id: int, interval_hours: float, mode: str) -> int:
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO schedules (target_id, interval_hours, mode,
                       enabled, next_run, created_at)
                   VALUES (?,?,?,1,?,?) RETURNING id""",
                (target_id, interval_hours, mode, _now(), _now()),
            )
            return cur.fetchone()[0]

    def list_schedules(self) -> list[dict]:
        with self.cursor() as cur:
            cur.execute(
                """SELECT s.*, t.url AS target_url, t.label AS target_label
                   FROM schedules s JOIN targets t ON t.id = s.target_id
                   ORDER BY s.created_at DESC"""
            )
            return [dict(r) for r in cur.fetchall()]

    def list_due_schedules(self) -> list[dict]:
        now = _now()
        with self.cursor() as cur:
            cur.execute(
                """SELECT s.*, t.url AS target_url FROM schedules s
                   JOIN targets t ON t.id = s.target_id
                   WHERE s.enabled=1 AND (s.next_run IS NULL OR s.next_run <= ?)""",
                (now,),
            )
            return [dict(r) for r in cur.fetchall()]

    def update_schedule(self, schedule_id: int, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        with self.cursor() as cur:
            cur.execute(
                f"UPDATE schedules SET {cols} WHERE id=?",
                (*fields.values(), schedule_id),
            )

    def delete_schedule(self, schedule_id: int) -> None:
        with self.cursor() as cur:
            cur.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))

    # ---- notifiers ----------------------------------------------------
    def create_notifier(self, kind: str, url: str, min_severity: str) -> int:
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO notifiers (kind, url, min_severity, enabled, created_at)
                   VALUES (?,?,?,1,?) RETURNING id""",
                (kind, url, min_severity, _now()),
            )
            return cur.fetchone()[0]

    def list_notifiers(self) -> list[dict]:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM notifiers ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]

    def delete_notifier(self, nid: int) -> None:
        with self.cursor() as cur:
            cur.execute("DELETE FROM notifiers WHERE id=?", (nid,))

    # ---- analytics ----------------------------------------------------
    def overview_stats(self) -> dict:
        with self.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM targets")
            target_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM scans")
            scan_count = cur.fetchone()[0]
            cur.execute(
                "SELECT severity, COUNT(*) FROM findings "
                "JOIN scans ON scans.id = findings.scan_id "
                "WHERE scans.status='done' GROUP BY severity"
            )
            by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for sev, c in cur.fetchall():
                by_sev[sev] = c
            cur.execute(
                """SELECT s.id, s.mode, s.status, s.risk_score, s.created_at,
                       t.url AS target_url, t.label AS target_label
                   FROM scans s JOIN targets t ON t.id = s.target_id
                   ORDER BY s.created_at DESC LIMIT 8"""
            )
            recent = [dict(r) for r in cur.fetchall()]
        return {
            "targets": target_count,
            "scans": scan_count,
            "findings_by_severity": by_sev,
            "total_findings": sum(by_sev.values()),
            "recent_scans": recent,
        }
