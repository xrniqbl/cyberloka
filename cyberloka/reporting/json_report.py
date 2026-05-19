"""JSON report exporter."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from cyberloka import __version__
from cyberloka.core import Finding, Target
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.explainer import build_executive_summary, explain_finding
from cyberloka.reporting.html_report import compute_risk_score


def write_json(path: str, target: Target, config: ScanConfig, findings: list[Finding]) -> None:
    risk_score, risk_label = compute_risk_score(findings)
    findings_dicts = [explain_finding(f.to_dict()) for f in findings]
    summary = _summary(findings)
    owasp = Counter()
    for f in findings_dicts:
        if f.get("owasp_category"):
            owasp[f["owasp_category"]] += 1

    data = {
        "tool": "cyberloka",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": {
            "raw": target.raw,
            "scheme": target.scheme,
            "host": target.host,
            "port": target.port,
            "is_ip": target.is_ip,
        },
        "scan": {
            "mode": config.mode,
            "modules": config.resolve_modules(),
            "simulate_attack": config.simulate_attack,
        },
        "risk": {"score": risk_score, "label": risk_label},
        "summary": summary,
        "executive_summary": build_executive_summary(
            findings_dicts, risk_score, risk_label, target.base_url
        ),
        "owasp_distribution": dict(owasp),
        "findings": findings_dicts,
    }
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, ensure_ascii=False)


def _summary(findings: list[Finding]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity.value] += 1
    return {"total": len(findings), "by_severity": counts}
