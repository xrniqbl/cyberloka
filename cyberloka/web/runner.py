"""Background scan runner: bridges Cyberloka's scanner to the DB."""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from cyberloka.core.config import ScanConfig
from cyberloka.core.logger import get_logger
from cyberloka.core.target import parse_target
from cyberloka.reporting.html_report import compute_risk_score
from cyberloka.scanner import run_scan
from cyberloka.web.db import Database

log = get_logger("cyberloka.web.runner")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def start_scan_thread(db: Database, scan_id: int, target_url: str, cfg: ScanConfig) -> None:
    """Launch the scan in a daemon thread; returns immediately."""

    def _worker() -> None:
        db.update_scan(scan_id, status="running", started_at=_now())
        try:
            target = parse_target(target_url)
        except Exception as e:  # noqa: BLE001
            db.update_scan(
                scan_id,
                status="error",
                error=f"Target invalid: {e}",
                finished_at=_now(),
            )
            return

        def progress(name: str, done: int, total: int) -> None:
            db.update_scan(
                scan_id,
                progress=done,
                progress_total=total,
                current_module=name,
            )

        try:
            findings = run_scan(target, cfg, progress_cb=progress)
        except Exception as e:  # noqa: BLE001
            log.exception("Scan %s gagal: %s", scan_id, e)
            db.update_scan(scan_id, status="error", error=str(e), finished_at=_now())
            return

        risk_score, risk_label = compute_risk_score(findings)
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            summary[f.severity.value] += 1

        db.insert_findings(scan_id, [f.to_dict() for f in findings])
        db.update_scan(
            scan_id,
            status="done",
            current_module=None,
            finished_at=_now(),
            risk_score=risk_score,
            risk_label=risk_label,
            summary_json=__import__("json").dumps(
                {"total": len(findings), "by_severity": summary}
            ),
        )

    threading.Thread(target=_worker, daemon=True, name=f"scan-{scan_id}").start()
