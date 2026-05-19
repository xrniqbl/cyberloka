"""HTML report exporter (Jinja2)."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cyberloka import __version__
from cyberloka.core import Finding, Target
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.explainer import (
    CATEGORIES,
    GLOSSARY,
    SEVERITY_ACTION,
    build_executive_summary,
    explain_finding,
)


CATEGORY_DESCRIPTIONS = {
    "data": (
        "Risiko terkait kerahasiaan data pelanggan (PII, transaksi, password) "
        "dan akses tidak sah ke data orang lain."
    ),
    "login": (
        "Risiko terkait proses autentikasi: cookie sesi, OTP, reset password, "
        "captcha, dan token JWT."
    ),
    "uang": (
        "Risiko keuangan langsung: manipulasi harga, voucher abuse, race "
        "condition pada saldo, kebocoran kunci payment gateway."
    ),
    "infra": (
        "Risiko di lapisan server, jaringan, dan konfigurasi infrastruktur."
    ),
    "email": (
        "Risiko pada pengiriman email dan keaslian domain (spoofing, phishing)."
    ),
    "kode": (
        "Risiko di kode aplikasi: library lama, CSP lemah, prototype pollution."
    ),
    "info": (
        "Bukan kerentanan langsung, tetapi membantu attacker memetakan "
        "permukaan serangan."
    ),
    "lain": (
        "Temuan yang tidak masuk kategori utama."
    ),
}


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


def _action_buckets(findings: list[dict]) -> dict[str, list[dict]]:
    buckets: dict[str, list[dict]] = {
        "critical": [], "high": [], "medium": [], "low": [], "info": [],
    }
    for f in findings:
        sev = f.get("severity", "info")
        if sev in buckets:
            buckets[sev].append(f)
    return buckets


def _categorize(findings: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for f in findings:
        cat = f.get("category_id", "lain")
        out.setdefault(cat, []).append(f)
    return out


def _owasp_distribution(findings: list[dict]) -> dict[str, int]:
    c: Counter = Counter()
    for f in findings:
        cat = f.get("owasp_category")
        if cat:
            c[cat] += 1
    return dict(c.most_common())


def write_html(path: str, target: Target, config: ScanConfig, findings: list[Finding]) -> None:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    findings_sorted = sorted(findings, key=lambda f: (f.severity.order, f.module))
    risk_score, risk_label = compute_risk_score(findings_sorted)
    findings_dicts = [explain_finding(f.to_dict()) for f in findings_sorted]
    summary = _summary(findings_sorted)

    # PDP-relevant counts
    pdp_pii = sum(1 for f in findings_dicts if f.get("module") == "pii_leak")
    pdp_idor = sum(1 for f in findings_dicts if f.get("module") == "idor_generic")
    pdp_cookie = sum(1 for f in findings_dicts if f.get("module") in ("cookies", "session"))
    pdp_tls = sum(1 for f in findings_dicts if f.get("module") == "tls")

    html = template.render(
        target=target,
        scan={"mode": config.mode, "modules": config.resolve_modules()},
        summary=summary,
        findings=findings_dicts,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        tool_version=__version__,
        risk_score=risk_score,
        risk_label=risk_label,
        exec=build_executive_summary(
            findings_dicts, risk_score, risk_label, target.base_url
        ),
        categories=_categorize(findings_dicts),
        category_labels=CATEGORIES,
        category_descriptions=CATEGORY_DESCRIPTIONS,
        action_buckets=_action_buckets(findings_dicts),
        severity_action=SEVERITY_ACTION,
        owasp_distribution=_owasp_distribution(findings_dicts),
        pdp_pii=pdp_pii,
        pdp_idor=pdp_idor,
        pdp_cookie=pdp_cookie,
        pdp_tls=pdp_tls,
        glossary=GLOSSARY,
    )
    Path(path).write_text(html, encoding="utf-8")
