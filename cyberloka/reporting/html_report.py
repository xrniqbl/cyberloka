"""HTML report exporter (Jinja2).

Template di-embed di kode + tetap bisa override pakai file
`templates/report.html` kalau ada. Ini supaya tool tidak crash bila
file template hilang (mis. saat user pull branch tanpa folder templates,
atau ekstrak zip yang skip file kosong).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cyberloka import __version__
from cyberloka.core import Finding, Target
from cyberloka.core.config import ScanConfig


# Embedded fallback template — identik dengan templates/report.html.
_DEFAULT_TEMPLATE = """<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<title>Cyberloka Report - {{ target.host }}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
  header { padding: 24px 32px; background: linear-gradient(135deg, #6d28d9, #db2777); }
  header h1 { margin: 0; font-size: 28px; letter-spacing: 1px; }
  header p { margin: 4px 0 0; opacity: 0.9; }
  main { max-width: 1100px; margin: 0 auto; padding: 24px; }
  .meta, .summary, .findings { background: #1e293b; border-radius: 12px; padding: 20px 24px; margin-bottom: 20px; }
  .meta dt { font-weight: 600; color: #94a3b8; }
  .meta dd { margin: 0 0 8px; }
  .summary table { border-collapse: collapse; width: 100%; }
  .summary th, .summary td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #334155; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-weight: 600; font-size: 12px; letter-spacing: 0.5px; }
  .sev-critical { background: #dc2626; color: #fff; }
  .sev-high     { background: #ef4444; color: #fff; }
  .sev-medium   { background: #f59e0b; color: #000; }
  .sev-low      { background: #38bdf8; color: #000; }
  .sev-info     { background: #475569; color: #e2e8f0; }
  .finding { border-left: 4px solid #6366f1; padding: 16px 18px; margin-bottom: 14px; background: #0f172a; border-radius: 8px; }
  .finding.crit { border-color: #dc2626; }
  .finding.high { border-color: #ef4444; }
  .finding.med  { border-color: #f59e0b; }
  .finding.low  { border-color: #38bdf8; }
  .finding.info { border-color: #475569; }
  .finding h3 { margin: 0 0 6px; font-size: 17px; }
  .finding .small { color: #94a3b8; font-size: 13px; margin-bottom: 10px; }
  .finding section { margin-top: 10px; }
  .finding section h4 { margin: 0 0 4px; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; color: #a5b4fc; }
  pre { background: #020617; padding: 10px 12px; border-radius: 6px; white-space: pre-wrap; word-break: break-word; font-size: 13px; color: #fde68a; }
  a { color: #93c5fd; }
  footer { padding: 16px 32px; text-align: center; color: #64748b; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>CYBERLOKA</h1>
  <p>Web Vulnerability Report - {{ generated_at }}</p>
</header>
<main>
  <section class="meta">
    <dl>
      <dt>Target</dt><dd>{{ target.scheme }}://{{ target.host }}{% if target.port not in (80, 443) %}:{{ target.port }}{% endif %}</dd>
      <dt>Mode</dt><dd>{{ scan.mode }}</dd>
      <dt>Modul yang dijalankan</dt><dd>{{ scan.modules|join(', ') }}</dd>
      <dt>Versi tool</dt><dd>{{ tool_version }}</dd>
    </dl>
  </section>

  <section class="summary">
    <h2>Ringkasan</h2>
    <table>
      <thead><tr><th>Severity</th><th>Jumlah</th></tr></thead>
      <tbody>
        {% for sev in ['critical','high','medium','low','info'] %}
        <tr>
          <td><span class="badge sev-{{ sev }}">{{ sev|upper }}</span></td>
          <td>{{ summary.by_severity[sev] }}</td>
        </tr>
        {% endfor %}
        <tr><td><b>TOTAL</b></td><td><b>{{ summary.total }}</b></td></tr>
      </tbody>
    </table>
  </section>

  <section class="findings">
    <h2>Findings</h2>
    {% if findings %}
      {% for f in findings %}
      {% set cls = {'critical':'crit','high':'high','medium':'med','low':'low','info':'info'}[f.severity] %}
      <article class="finding {{ cls }}">
        <h3><span class="badge sev-{{ f.severity }}">{{ f.severity|upper }}</span> {{ f.title }}</h3>
        <div class="small">module: <b>{{ f.module }}</b> &middot; target: {{ f.target }}{% if f.cwe %} &middot; {{ f.cwe }}{% endif %} &middot; confidence: {{ f.confidence }}</div>
        <section><h4>Deskripsi</h4><div>{{ f.description }}</div></section>
        {% if f.evidence %}<section><h4>Evidence</h4><pre>{{ f.evidence }}</pre></section>{% endif %}
        {% if f.remediation %}<section><h4>Remediasi</h4><div>{{ f.remediation }}</div></section>{% endif %}
        {% if f.references %}
        <section><h4>Referensi</h4>
          <ul>{% for r in f.references %}<li><a href="{{ r }}" target="_blank" rel="noopener">{{ r }}</a></li>{% endfor %}</ul>
        </section>
        {% endif %}
      </article>
      {% endfor %}
    {% else %}
      <p>Tidak ada finding.</p>
    {% endif %}
  </section>
</main>
<footer>Generated by Cyberloka {{ tool_version }}. Use only on systems you are authorized to test.</footer>
</body>
</html>
"""


def _summary(findings: list[Finding]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity.value] += 1
    return {"total": len(findings), "by_severity": counts}


def _get_template(env: Environment, template_dir: Path):
    """Coba load report.html dari folder; kalau tidak ada, pakai embedded default."""
    candidate = template_dir / "report.html"
    if candidate.exists():
        return env.get_template("report.html")
    # Fallback: render dari string
    return env.from_string(_DEFAULT_TEMPLATE)


def write_html(path: str, target: Target, config: ScanConfig, findings: list[Finding]) -> None:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)) if template_dir.exists() else None,
        autoescape=select_autoescape(["html"]),
    )
    template = _get_template(env, template_dir)
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
