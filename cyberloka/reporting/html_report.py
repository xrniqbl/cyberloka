"""HTML report exporter (Jinja2)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cyberloka import __version__
from cyberloka.core import Finding, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.report_bundle import build_bundle


def write_html(
    path: str, target: Target, config: ScanConfig, findings: list[Finding]
) -> None:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    bundle = build_bundle(target, config, findings)
    html = template.render(
        bundle=bundle,
        exec_summary=bundle["executive_summary"],
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        tool_version=__version__,
    )
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(html, encoding="utf-8")
