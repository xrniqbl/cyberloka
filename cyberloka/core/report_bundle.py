"""Unified report bundle.

Combines findings + risk score + compliance mapping + executive summary into
a single dictionary that all reporters (JSON, HTML, console, dashboard)
consume. This guarantees consistent numbers across every output channel.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from cyberloka import __version__
from cyberloka.core.compliance import compliance_summary, map_finding
from cyberloka.core.config import ScanConfig
from cyberloka.core.finding import Finding
from cyberloka.core.risk import (
    build_executive_summary,
    score_finding,
    severity_band,
)
from cyberloka.core.target import Target


def build_bundle(
    target: Target, config: ScanConfig, findings: list[Finding]
) -> dict[str, Any]:
    """Return a JSON-serialisable dict with everything a reporter needs."""
    enriched: list[dict[str, Any]] = []
    for f in findings:
        d = f.to_dict()
        score = score_finding(f)
        d["risk_score"] = score
        d["risk_band"] = severity_band(score)
        mapping = map_finding(f)
        d["compliance"] = mapping.to_dict()
        d["compliance_tags"] = mapping.as_flat_tags()
        enriched.append(d)

    # Sort by risk score (high -> low) so reporters get a stable order.
    enriched.sort(
        key=lambda r: (-r["risk_score"], r["severity"], r["module"])
    )

    summary = build_executive_summary(findings)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity.value] += 1

    return {
        "tool": "cyberloka",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": {
            "raw": target.raw,
            "scheme": target.scheme,
            "host": target.host,
            "port": target.port,
            "is_ip": target.is_ip,
            "base_url": target.base_url,
        },
        "scan": {
            "mode": config.mode,
            "modules": config.resolve_modules(),
            "simulate_attack": config.simulate_attack,
        },
        "summary": {
            "total": len(findings),
            "by_severity": counts,
        },
        "executive_summary": asdict(summary),
        "compliance_summary": compliance_summary(findings),
        "findings": enriched,
    }
