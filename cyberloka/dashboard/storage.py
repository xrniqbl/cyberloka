"""Filesystem-backed storage for scan report bundles.

The dashboard does not need a database — every scan is just a JSON file in a
reports directory. This module loads and indexes those files.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ScanRecord:
    """One entry in the scan history index."""

    scan_id: str          # filename stem, used as URL-safe id
    path: Path
    target: str
    host: str
    mode: str
    grade: str
    score: float
    total_findings: int
    by_severity: dict[str, int]
    generated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "host": self.host,
            "mode": self.mode,
            "grade": self.grade,
            "score": self.score,
            "total_findings": self.total_findings,
            "by_severity": self.by_severity,
            "generated_at": self.generated_at,
        }


class ReportStore:
    """Lazy, thread-safe index over a reports directory."""

    def __init__(self, reports_dir: str | Path):
        self.reports_dir = Path(reports_dir)
        self._lock = threading.Lock()

    def ensure(self) -> None:
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Index
    # ------------------------------------------------------------------

    def list_scans(self) -> list[ScanRecord]:
        """Return all scan records sorted newest-first."""
        self.ensure()
        records: list[ScanRecord] = []
        with self._lock:
            for jf in sorted(self.reports_dir.glob("*.json")):
                try:
                    rec = self._load_record(jf)
                except Exception:  # noqa: BLE001 — be tolerant of malformed files
                    continue
                if rec is not None:
                    records.append(rec)
        records.sort(key=lambda r: r.generated_at, reverse=True)
        return records

    def get_bundle(self, scan_id: str) -> dict[str, Any] | None:
        """Return the full JSON bundle for a scan, or None if missing."""
        path = self.reports_dir / f"{scan_id}.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return None

    # ------------------------------------------------------------------
    # Aggregations
    # ------------------------------------------------------------------

    def by_host(self) -> dict[str, list[ScanRecord]]:
        out: dict[str, list[ScanRecord]] = {}
        for r in self.list_scans():
            out.setdefault(r.host, []).append(r)
        for v in out.values():
            v.sort(key=lambda r: r.generated_at)  # oldest -> newest for trends
        return out

    def trend_for_host(self, host: str) -> list[dict[str, Any]]:
        """Return a list of {generated_at, score, grade, total_findings, by_severity} for charts."""
        scans = self.by_host().get(host, [])
        return [
            {
                "generated_at": s.generated_at,
                "score": s.score,
                "grade": s.grade,
                "total_findings": s.total_findings,
                "by_severity": s.by_severity,
                "scan_id": s.scan_id,
            }
            for s in scans
        ]

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _load_record(self, path: Path) -> ScanRecord | None:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("tool") != "cyberloka":
            return None
        target = data.get("target", {})
        scan = data.get("scan", {})
        summary = data.get("summary", {})
        exec_summary = data.get("executive_summary", {})
        return ScanRecord(
            scan_id=path.stem,
            path=path,
            target=target.get("base_url") or target.get("raw") or "",
            host=target.get("host") or "",
            mode=scan.get("mode", ""),
            grade=exec_summary.get("grade", "?"),
            score=float(exec_summary.get("overall_score", 0.0)),
            total_findings=int(summary.get("total", 0)),
            by_severity=summary.get("by_severity", {}),
            generated_at=data.get("generated_at", ""),
        )
