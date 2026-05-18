"""HTML report exporter (Jinja2)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cyberloka import __version__
from cyberloka.core import Finding, Target
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.extras import IMPACT_MAP, MITRE_MAP, OWASP_MAP, REPRO_MAP
from cyberloka.reporting.scenarios import get_scenario, is_access_gained


def _summary(findings: list[Finding]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity.value] += 1
    return {"total": len(findings), "by_severity": counts}


def _enrich_finding_dict(f: Finding, target: Target) -> dict:
    d = f.to_dict()
    sc = get_scenario(f.module)
    d["scenario_what"] = sc.get("what", "")
    d["scenario_exploit"] = sc.get("exploit", "")
    d["scenario_mitigate"] = sc.get("mitigate", "")
    d["owasp"] = OWASP_MAP.get(f.module)
    d["mitre"] = MITRE_MAP.get(f.module)
    d["impact"] = IMPACT_MAP.get(f.module)
    repro = REPRO_MAP.get(f.module)
    if repro:
        url_for_repro = (f.urls[0] if f.urls else target.base_url)
        try:
            d["repro"] = repro.format(url=url_for_repro, host=target.host)
        except Exception:  # noqa: BLE001
            d["repro"] = repro
    else:
        d["repro"] = ""
    gained, label = is_access_gained(f)
    d["access_gained"] = gained
    d["access_label"] = label
    return d


def write_html(path: str, target: Target, config: ScanConfig, findings: list[Finding]) -> None:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    findings_sorted = sorted(findings, key=lambda f: (f.severity.order, f.module))
    enriched = [_enrich_finding_dict(f, target) for f in findings_sorted]
    html = template.render(
        target=target,
        scan={"mode": config.mode, "modules": config.resolve_modules()},
        summary=_summary(findings),
        findings=enriched,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        tool_version=__version__,
    )
    Path(path).write_text(html, encoding="utf-8")
