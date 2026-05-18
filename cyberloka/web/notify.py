"""Outbound notifications for high-severity findings.

Supports three kinds:

- webhook: POST JSON to URL.
- slack:   POST {"text": ...} to a Slack incoming-webhook URL.
- email:   send via SMTP (env vars CYBERLOKA_SMTP_HOST/PORT/USER/PASS/FROM).
"""
from __future__ import annotations

import json
import os
import smtplib
from email.mime.text import MIMEText

import requests

from cyberloka.core.logger import get_logger

log = get_logger("cyberloka.web.notify")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _filter_findings(findings: list[dict], min_severity: str) -> list[dict]:
    threshold = SEVERITY_ORDER.get(min_severity, 1)
    return [f for f in findings if SEVERITY_ORDER.get(f.get("severity", "info"), 4) <= threshold]


def _summary_text(scan: dict, findings: list[dict]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    parts = " · ".join(f"{k}: {v}" for k, v in sorted(
        counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 4)
    ))
    label = scan.get("target_label") or scan.get("target_url") or "target"
    return (
        f"[Cyberloka] Scan #{scan['id']} {label}\n"
        f"Mode: {scan.get('mode')} · Risk: {scan.get('risk_score')} ({scan.get('risk_label')})\n"
        f"Findings (>= threshold): {parts or 'none'}"
    )


def _send_webhook(url: str, payload: dict) -> None:
    try:
        requests.post(url, json=payload, timeout=10)
    except requests.RequestException as e:
        log.warning("webhook gagal: %s", e)


def _send_slack(url: str, scan: dict, findings: list[dict]) -> None:
    text = _summary_text(scan, findings)
    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": "*" + text.replace("\n", "*\n*") + "*"}},
    ]
    top = findings[:5]
    if top:
        lines = [f"• *[{f['severity'].upper()}]* `{f['module']}` — {f['title']}" for f in top]
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn", "text": "\n".join(lines)}})
    try:
        requests.post(url, json={"text": text, "blocks": blocks}, timeout=10)
    except requests.RequestException as e:
        log.warning("slack gagal: %s", e)


def _send_email(mailto: str, scan: dict, findings: list[dict]) -> None:
    host = os.environ.get("CYBERLOKA_SMTP_HOST")
    if not host:
        log.info("CYBERLOKA_SMTP_HOST tidak diset, lewati notifikasi email.")
        return
    port = int(os.environ.get("CYBERLOKA_SMTP_PORT", "587"))
    user = os.environ.get("CYBERLOKA_SMTP_USER")
    pwd = os.environ.get("CYBERLOKA_SMTP_PASS")
    sender = os.environ.get("CYBERLOKA_SMTP_FROM", user or "cyberloka@example.invalid")

    body = _summary_text(scan, findings)
    body += "\n\nDetail:\n" + "\n".join(
        f"- [{f['severity'].upper()}] {f['module']}: {f['title']}"
        for f in findings[:20]
    )
    msg = MIMEText(body)
    msg["Subject"] = f"[Cyberloka] Scan #{scan['id']} {scan.get('target_label', '')}"
    msg["From"] = sender
    msg["To"] = mailto.replace("mailto:", "")
    try:
        with smtplib.SMTP(host, port, timeout=15) as s:
            s.starttls()
            if user and pwd:
                s.login(user, pwd)
            s.sendmail(sender, [msg["To"]], msg.as_string())
    except Exception as e:  # noqa: BLE001
        log.warning("email gagal: %s", e)


def fire(notifiers: list[dict], scan: dict, findings: list[dict]) -> None:
    for n in notifiers:
        if not n.get("enabled"):
            continue
        relevant = _filter_findings(findings, n.get("min_severity", "high"))
        if not relevant:
            continue
        kind = n["kind"]
        url = n.get("url") or ""
        try:
            if kind == "webhook":
                _send_webhook(url, {
                    "scan": scan,
                    "findings": relevant,
                    "summary": _summary_text(scan, relevant),
                })
            elif kind == "slack":
                _send_slack(url, scan, relevant)
            elif kind == "email":
                _send_email(url, scan, relevant)
            else:
                log.warning("Unknown notifier kind: %s", kind)
        except Exception as e:  # noqa: BLE001
            log.warning("Notifier %s error: %s", kind, e)
