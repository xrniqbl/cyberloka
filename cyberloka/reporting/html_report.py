"""HTML report exporter (Jinja2)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cyberloka import __version__
from cyberloka.core import Finding, Target
from cyberloka.core.config import ScanConfig


def _summary(findings: list[Finding]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity.value] += 1
    return {"total": len(findings), "by_severity": counts}


def compute_risk_score(findings: list[Finding]) -> tuple[int, str]:
    """Aggregate risk score 0-100 + label."""
    if not findings:
        return 0, "No findings"
    weights = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
    score = sum(weights[f.severity.value] for f in findings)
    score = min(100, score)
    if score >= 75:
        label = "Critical posture"
    elif score >= 50:
        label = "High risk"
    elif score >= 25:
        label = "Moderate risk"
    elif score > 0:
        label = "Low risk"
    else:
        label = "Healthy"
    return score, label


def write_html(path: str, target: Target, config: ScanConfig, findings: list[Finding]) -> None:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    findings_sorted = sorted(findings, key=lambda f: (f.severity.order, f.module))
    risk_score, risk_label = compute_risk_score(findings_sorted)
    html = template.render(
        target=target,
        scan={"mode": config.mode, "modules": config.resolve_modules()},
        summary=_summary(findings),
        findings=[f.to_dict() for f in findings_sorted],
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        tool_version=__version__,
        risk_score=risk_score,
        risk_label=risk_label,
    )
    Path(path).write_text(html, encoding="utf-8")
