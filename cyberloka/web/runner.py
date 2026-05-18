"""Background scan runner + scheduler thread."""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone

from cyberloka.core.config import ScanConfig
from cyberloka.core.logger import get_logger
from cyberloka.core.target import parse_target
from cyberloka.reporting.html_report import compute_risk_score
from cyberloka.scanner import run_scan
from cyberloka.web import notify
from cyberloka.web.db import Database

log = get_logger("cyberloka.web.runner")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _execute(db: Database, scan_id: int, target_url: str, cfg: ScanConfig) -> None:
    db.update_scan(scan_id, status="running", started_at=_now())
    try:
        target = parse_target(target_url)
    except Exception as e:  # noqa: BLE001
        db.update_scan(
            scan_id, status="error",
            error=f"Target invalid: {e}", finished_at=_now(),
        )
        return

    def progress(name: str, done: int, total: int) -> None:
        db.update_scan(
            scan_id, progress=done, progress_total=total, current_module=name,
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

    finding_dicts = [f.to_dict() for f in findings]
    db.insert_findings(scan_id, finding_dicts)
    db.update_scan(
        scan_id, status="done", current_module=None, finished_at=_now(),
        risk_score=risk_score, risk_label=risk_label,
        summary_json=json.dumps({"total": len(findings), "by_severity": summary}),
    )

    # Notifikasi
    try:
        scan = db.get_scan(scan_id)
        notifiers = db.list_notifiers()
        if scan and notifiers:
            notify.fire(notifiers, scan, finding_dicts)
    except Exception as e:  # noqa: BLE001
        log.warning("notifier dispatch error: %s", e)


def start_scan_thread(db: Database, scan_id: int, target_url: str, cfg: ScanConfig) -> None:
    """Launch the scan in a daemon thread."""
    threading.Thread(
        target=_execute, args=(db, scan_id, target_url, cfg),
        daemon=True, name=f"scan-{scan_id}",
    ).start()


def _scheduler_loop(db_path: str | None) -> None:
    log.info("[scheduler] started")
    while True:
        try:
            db = Database(db_path) if db_path else Database()
            for sched in db.list_due_schedules():
                try:
                    target = db.get_target(sched["target_id"])
                    if not target:
                        continue
                    cfg = ScanConfig(
                        target=target["url"], mode=sched["mode"], authorized=True,
                    )
                    resolved = cfg.resolve_modules()
                    scan_id = db.create_scan(target["id"], cfg.mode, resolved, len(resolved))
                    next_run = (
                        datetime.now(timezone.utc)
                        + timedelta(hours=float(sched["interval_hours"]))
                    ).isoformat()
                    db.update_schedule(
                        sched["id"], last_run=_now(), next_run=next_run,
                    )
                    log.info("[scheduler] firing scan #%s for target %s", scan_id, target["url"])
                    start_scan_thread(db, scan_id, target["url"], cfg)
                except Exception as e:  # noqa: BLE001
                    log.warning("[scheduler] fail to dispatch %s: %s", sched.get("id"), e)
        except Exception as e:  # noqa: BLE001
            log.warning("[scheduler] loop error: %s", e)
        time.sleep(60)


_scheduler_started = False
_scheduler_lock = threading.Lock()


def ensure_scheduler(db_path: str | None = None) -> None:
    """Start scheduler thread once per process."""
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        threading.Thread(
            target=_scheduler_loop, args=(db_path,),
            daemon=True, name="cyberloka-scheduler",
        ).start()
        _scheduler_started = True
