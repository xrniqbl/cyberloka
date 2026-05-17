"""Plain-text (.txt) report exporter.

Renders the unified report bundle into a clean, monospaced summary that
non-technical readers can email, paste into a ticket, or open in any editor.
Keeps the same sections as the HTML report: header / executive summary /
top priorities / compliance mapping / per-finding detail.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cyberloka import __version__
from cyberloka.core import Finding, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.report_bundle import build_bundle


_FW_TITLES = {
    "owasp_2021": "OWASP Top 10 2021",
    "pci_dss_v4": "PCI-DSS v4.0",
    "iso_27001":  "ISO/IEC 27001:2022",
    "nist_csf":   "NIST CSF 2.0",
    "cis_v8":     "CIS Controls v8",
    "uu_pdp":     "UU PDP Indonesia (UU 27/2022)",
}


def _hr(char: str = "=", width: int = 78) -> str:
    return char * width


def _section(title: str) -> str:
    return f"\n{_hr('=')}\n  {title}\n{_hr('=')}\n"


def _wrap(text: str, indent: str = "  ", width: int = 76) -> str:
    """Word-wrap text at `width` columns with `indent` on every line."""
    out: list[str] = []
    for raw in (text or "").splitlines() or [""]:
        if not raw.strip():
            out.append("")
            continue
        line = ""
        for word in raw.split():
            if line and len(line) + len(word) + 1 > width:
                out.append(indent + line)
                line = word
            else:
                line = (line + " " + word) if line else word
        if line:
            out.append(indent + line)
    return "\n".join(out)


def _kv(key: str, value: str, width: int = 14) -> str:
    return f"  {key:<{width}}: {value}"


def render_txt(target: Target, config: ScanConfig, findings: list[Finding]) -> str:
    bundle = build_bundle(target, config, findings)
    es = bundle["executive_summary"]
    summary = bundle["summary"]
    counts = es["by_severity"]
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    out: list[str] = []

    # ---- Header ------------------------------------------------------------
    out.append(_hr("#"))
    out.append("#" + " CYBERLOKA SECURITY REPORT ".center(76) + "#")
    out.append(_hr("#"))
    out.append("")
    out.append(_kv("Target", bundle["target"]["base_url"] or bundle["target"]["raw"]))
    out.append(_kv("Host", bundle["target"]["host"] or "-"))
    out.append(_kv("Mode", bundle["scan"]["mode"]))
    out.append(_kv("Modules", str(len(bundle["scan"]["modules"]))))
    out.append(_kv("Generated", generated_at))
    out.append(_kv("Tool", f"cyberloka {__version__}"))

    # ---- Executive summary -------------------------------------------------
    out.append(_section("EXECUTIVE SUMMARY"))
    out.append(
        f"  Grade: {es['grade']:<3}    "
        f"Score: {es['overall_score']:.1f} / 100    "
        f"({es['grade_label']})"
    )
    out.append("")
    out.append(_wrap(es["posture"]))
    out.append("")
    out.append(
        "  Findings: "
        f"Critical {counts['critical']}  |  "
        f"High {counts['high']}  |  "
        f"Medium {counts['medium']}  |  "
        f"Low {counts['low']}  |  "
        f"Info {counts['info']}"
    )
    out.append(
        f"  Total: {summary['total']} ({es['actionable_findings']} actionable)"
    )
    vstats = summary.get("verification") or {}
    if vstats.get("verified"):
        out.append(
            "  Verification: "
            f"verified={vstats.get('verified', 0)}  "
            f"confirmed={vstats.get('confirmed', 0)}  "
            f"firm={vstats.get('firm', 0)}  "
            f"tentative={vstats.get('tentative', 0)}  "
            f"false_positive={vstats.get('false_positive', 0)}"
        )

    # ---- Top priorities ----------------------------------------------------
    if es.get("top_priorities"):
        out.append(_section("TOP 5 PRIORITAS PERBAIKAN"))
        out.append(f"  {'#':<3}{'Risk':>5}  {'Severity':<9} {'Module':<14} Issue")
        out.append("  " + "-" * 76)
        for i, p in enumerate(es["top_priorities"], 1):
            title = (p["title"] or "")[:50]
            out.append(
                f"  {i:<3}{p['score']:>5.1f}  {p['severity']:<9} {p['module']:<14} {title}"
            )

    # ---- Compliance mapping ------------------------------------------------
    out.append(_section("COMPLIANCE MAPPING"))
    any_compl = False
    for fw, rows in bundle["compliance_summary"].items():
        if not rows:
            continue
        any_compl = True
        out.append(f"\n  [{_FW_TITLES.get(fw, fw)}]")
        out.append(f"    {'Clause':<14} {'Findings':>9} {'Weight':>7}  Description")
        out.append("    " + "-" * 74)
        for r in rows:
            label = (r["label"] or "")[:42]
            out.append(
                f"    {r['id']:<14} {r['count']:>9} {r['weight']:>7}  {label}"
            )
    if not any_compl:
        out.append("  (Tidak ada finding yang ter-map ke kontrol compliance.)")

    # ---- Findings detail ---------------------------------------------------
    out.append(_section(f"FINDINGS ({len(bundle['findings'])})"))
    if not bundle["findings"]:
        out.append("  Tidak ada finding.")
    for i, f in enumerate(bundle["findings"], 1):
        out.append("")
        out.append(_hr("-"))
        sev = (f.get("severity") or "info").upper()
        score = f.get("risk_score", 0.0)
        out.append(
            f"  [{i:03d}] [{sev}] (risk {score:.1f}/10) {f.get('title', '')}"
        )
        if f.get("verification"):
            v = f["verification"]
            out.append(
                f"        verification: {v.get('status', '?').upper().replace('_', ' ')}"
            )
        out.append(_hr("-"))
        out.append(_kv("Module", f.get("module", "-")))
        out.append(_kv("Target", f.get("target", "-")))
        if f.get("cwe"):
            out.append(_kv("CWE", f["cwe"]))
        if f.get("compliance_tags"):
            out.append(_kv("Compliance", ", ".join(f["compliance_tags"])))
        out.append("")
        out.append("  Deskripsi:")
        out.append(_wrap(f.get("description", "")))
        if f.get("evidence"):
            out.append("")
            out.append("  Evidence:")
            out.append(_wrap(f["evidence"]))
        if f.get("remediation"):
            out.append("")
            out.append("  Remediasi:")
            out.append(_wrap(f["remediation"]))
        if f.get("references"):
            out.append("")
            out.append("  Referensi:")
            for r in f["references"]:
                out.append(f"    - {r}")
        if f.get("verification"):
            v = f["verification"]
            out.append("")
            out.append("  Verification Detail:")
            if v.get("evidence_strong"):
                out.append(_wrap(v["evidence_strong"]))
            for a in v.get("attempts") or []:
                marker = "[+]" if a.get("success") else "[-]"
                detail = a.get("detail") or a.get("payload") or ""
                out.append(f"    {marker} {a.get('technique', '?'):<14} {detail}")
            if v.get("poc"):
                out.append("")
                out.append("  PoC:")
                out.append(f"    {v['poc']}")

    out.append("")
    out.append(_hr("="))
    out.append(f"  Generated by Cyberloka {__version__} - {generated_at}")
    out.append(_hr("="))
    out.append("")
    return "\n".join(out)


def write_txt(
    path: str, target: Target, config: ScanConfig, findings: list[Finding]
) -> None:
    text = render_txt(target, config, findings)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8")
