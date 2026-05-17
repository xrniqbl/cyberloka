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


def write_html(path: str, target: Target, config: ScanConfig, findings: list[Finding]) -> None:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    findings_sorted = sorted(findings, key=lambda f: (f.severity.order, f.module))
    html = template.render(
        target=target,
        scan={"mode": config.mode, "modules": config.resolve_modules()},
        summary=_summary(findings),
        findings=[f.to_dict() for f in findings_sorted],
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        tool_version=__version__,
    )
    Path(path).write_text(html, encoding="utf-8")
