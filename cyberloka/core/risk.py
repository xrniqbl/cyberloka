"""Risk scoring engine.

Assigns a CVSS-like numeric score (0.0 - 10.0) to each finding based on
severity, module class, exploitability, and confidence. Aggregates per-finding
scores into an overall website grade (A/B/C/D/F) — similar in spirit to the
SSL Labs grading model — and produces an executive summary suitable for
non-technical stakeholders.

The scoring is deterministic (not a real CVSS v3.1 vector calculation, which
would require per-finding metric mapping that the scanner does not have access
to) but reflects industry-aligned weights so the numbers stay defensible.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from cyberloka.core.finding import Finding, Severity


# Base score per severity, anchored to CVSS v3.1 severity bands:
#   Critical 9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, Low 0.1-3.9, Info 0.0
_SEVERITY_BASE: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.0,
}

# Per-module exploitability adjustment. Active exploitation primitives that
# typically yield direct compromise are boosted; informational/recon checks
# are dampened.
_MODULE_WEIGHT: dict[str, float] = {
    # active exploitation
    "sqli": 1.05,
    "cmdi": 1.05,
    "lfi": 1.0,
    "xss": 0.95,
    "redirect": 0.85,
    "dirlist": 0.85,
    # transport / config
    "tls": 1.0,
    "cookies": 0.9,
    "headers": 0.85,
    "cors": 0.95,
    "clickjacking": 0.85,
    "methods": 0.85,
    "sensitive_files": 1.0,
    "robots": 0.5,
    # recon / fingerprint -> mostly informational
    "fingerprint": 0.5,
    "dns": 0.5,
    "whois": 0.4,
    "ports": 0.7,
    "subdomains": 0.6,
    # simulate
    "burst": 0.8,
    "rate_limit": 0.9,
}

# Confidence multiplier (CVSS analogue: tentative ~ "Reasonable",
# confirmed ~ "Confirmed").
_CONFIDENCE_WEIGHT: dict[str, float] = {
    "tentative": 0.75,
    "firm": 1.0,
    "confirmed": 1.05,
}


def score_finding(finding: Finding) -> float:
    """Return a 0.0-10.0 risk score for a single finding."""
    base = _SEVERITY_BASE.get(finding.severity, 0.0)
    if base == 0.0:
        return 0.0
    mod_w = _MODULE_WEIGHT.get(finding.module, 0.9)
    conf_w = _CONFIDENCE_WEIGHT.get(finding.confidence, 1.0)
    score = base * mod_w * conf_w
    # Clamp to CVSS-style 0-10 with one decimal of precision.
    score = max(0.0, min(10.0, score))
    return round(score, 1)


def severity_band(score: float) -> str:
    """Map a numeric score back to its CVSS severity band."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


# ---------------------------------------------------------------------------
# Aggregate website grade
# ---------------------------------------------------------------------------


# Penalty applied to the 100-point baseline per finding-class.
# Critical/High dominate; lows nudge the grade down only mildly.
_GRADE_PENALTY: dict[Severity, float] = {
    Severity.CRITICAL: 35.0,
    Severity.HIGH: 18.0,
    Severity.MEDIUM: 7.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
}

# Diminishing returns: the n-th finding of a given severity contributes
# less than the first one (saturates around 1.0x multiplier).
_DIMINISH: dict[Severity, float] = {
    Severity.CRITICAL: 0.8,
    Severity.HIGH: 0.7,
    Severity.MEDIUM: 0.6,
    Severity.LOW: 0.4,
    Severity.INFO: 0.0,
}


def overall_score(findings: Iterable[Finding]) -> float:
    """Return a 0-100 composite security score for the whole target."""
    score = 100.0
    counts: dict[Severity, int] = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
        n = counts[f.severity]
        # First finding gets full penalty; subsequent ones decay geometrically.
        decay = _DIMINISH[f.severity] ** (n - 1)
        score -= _GRADE_PENALTY[f.severity] * decay
    return max(0.0, min(100.0, round(score, 1)))


def grade_from_score(score: float) -> str:
    """Map a 0-100 composite score to an SSL-Labs-style letter grade."""
    if score >= 95.0:
        return "A+"
    if score >= 85.0:
        return "A"
    if score >= 75.0:
        return "B"
    if score >= 60.0:
        return "C"
    if score >= 40.0:
        return "D"
    return "F"


_GRADE_LABEL: dict[str, str] = {
    "A+": "Excellent",
    "A": "Strong",
    "B": "Good",
    "C": "Adequate",
    "D": "Weak",
    "F": "Failing",
}


def grade_label(grade: str) -> str:
    return _GRADE_LABEL.get(grade, "")


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------


@dataclass
class ExecutiveSummary:
    """One-page management view of a scan."""

    overall_score: float           # 0-100
    grade: str                     # A+ .. F
    grade_label: str               # human label
    posture: str                   # short narrative for management
    by_severity: dict[str, int]
    total_findings: int
    actionable_findings: int       # everything except "info"
    top_priorities: list[dict]     # top 5 priorities (highest score first)


def _posture_narrative(grade: str, counts: dict[str, int]) -> str:
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    med = counts.get("medium", 0)

    if grade == "A+":
        return (
            "Postur keamanan website sangat baik. Tidak ada celah signifikan "
            "yang teridentifikasi. Pertahankan kontrol dan monitoring berkala."
        )
    if grade == "A":
        return (
            "Postur keamanan website kuat. Hanya ditemukan isu minor. "
            "Lakukan perbaikan rutin untuk mempertahankan grade."
        )
    if grade == "B":
        return (
            f"Postur keamanan baik tetapi perlu perhatian: {high} isu high "
            f"dan {med} isu medium ditemukan. Prioritaskan remediasi sebelum "
            "rilis berikutnya."
        )
    if grade == "C":
        return (
            f"Postur keamanan cukup. Terdapat {high} isu high dan {med} "
            "isu medium yang harus diperbaiki dalam waktu dekat. Risiko "
            "operasional moderat."
        )
    if grade == "D":
        prefix = f"{crit} isu critical dan " if crit else ""
        return (
            f"Postur keamanan lemah. {prefix}{high} isu high terbuka. "
            "Disarankan menunda go-live / rilis hingga remediasi selesai."
        )
    # F
    prefix = f"{crit} isu critical aktif" if crit else f"{high} isu high aktif"
    return (
        f"Postur keamanan kritis: {prefix}. Aplikasi rentan terhadap "
        "kompromi data dan layanan. Hentikan eksposur publik bila memungkinkan "
        "dan eskalasi penanganan ke incident response."
    )


def top_priorities(
    findings: Iterable[Finding], limit: int = 5
) -> list[dict]:
    """Return top-N findings sorted by exploitability x impact (risk score)."""
    scored: list[tuple[float, Finding]] = []
    for f in findings:
        s = score_finding(f)
        if s <= 0:
            continue
        scored.append((s, f))
    scored.sort(key=lambda x: (-x[0], x[1].severity.order, x[1].module))
    out: list[dict] = []
    for s, f in scored[:limit]:
        out.append(
            {
                "score": s,
                "severity": f.severity.value,
                "module": f.module,
                "title": f.title,
                "target": f.target,
                "remediation": f.remediation,
                "cwe": f.cwe,
            }
        )
    return out


def build_executive_summary(findings: list[Finding]) -> ExecutiveSummary:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity.value] += 1
    score = overall_score(findings)
    grade = grade_from_score(score)
    return ExecutiveSummary(
        overall_score=score,
        grade=grade,
        grade_label=grade_label(grade),
        posture=_posture_narrative(grade, counts),
        by_severity=counts,
        total_findings=len(findings),
        actionable_findings=sum(v for k, v in counts.items() if k != "info"),
        top_priorities=top_priorities(findings, limit=5),
    )


def annotate_findings(findings: list[Finding]) -> list[dict]:
    """Convert findings to dicts enriched with risk score + band."""
    out: list[dict] = []
    for f in findings:
        d = f.to_dict()
        d["risk_score"] = score_finding(f)
        d["risk_band"] = severity_band(d["risk_score"])
        out.append(d)
    return out
