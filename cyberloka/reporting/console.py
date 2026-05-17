"""Rich console reporter."""
from __future__ import annotations

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cyberloka.core import Finding, Severity
from cyberloka.core.compliance import compliance_summary, map_finding
from cyberloka.core.logger import get_console
from cyberloka.core.risk import (
    build_executive_summary,
    score_finding,
    severity_band,
)

SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "dim",
}

GRADE_STYLE = {
    "A+": "bold white on green",
    "A": "bold green",
    "B": "bold cyan",
    "C": "bold yellow",
    "D": "bold magenta",
    "F": "bold white on red",
}

_VSTATUS_STYLE = {
    "confirmed": "bold white on green",
    "firm": "bold cyan",
    "tentative": "yellow",
    "false_positive": "bold white on grey50",
}


def render_banner(target: str, mode: str, modules: list[str]) -> None:
    console = get_console()
    title = Text("CYBERLOKA", style="bold magenta")
    sub = Text("Web Vulnerability Scanner & Remediation Advisor", style="dim")
    body = Text.assemble(
        ("Target  : ", "bold"), (target + "\n", "cyan"),
        ("Mode    : ", "bold"), (mode + "\n", "cyan"),
        ("Modules : ", "bold"), (", ".join(modules), "cyan"),
    )
    console.print(
        Panel.fit(
            Text.assemble(title, "\n", sub, "\n\n", body),
            border_style="magenta",
        )
    )


def render_findings(findings: list[Finding]) -> None:
    console = get_console()
    if not findings:
        console.print("[green]Tidak ada finding.[/green]")
        return

    findings_sorted = sorted(
        findings,
        key=lambda f: (-score_finding(f), f.severity.order, f.module),
    )
    table = Table(title="Findings", show_lines=False, expand=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Score", width=6, justify="right")
    table.add_column("Severity", width=10)
    table.add_column("Module", width=14)
    table.add_column("Title", overflow="fold")
    for i, f in enumerate(findings_sorted, 1):
        score = score_finding(f)
        score_text = Text(f"{score:.1f}", style="bold")
        table.add_row(
            str(i),
            score_text,
            Text(f.severity.value.upper(), style=SEV_STYLE[f.severity]),
            f.module,
            f.title,
        )
    console.print(table)


def _compliance_one_liner(f: Finding) -> str:
    mapping = map_finding(f)
    parts: list[str] = []
    if mapping.owasp_2021:
        parts.append("OWASP " + ",".join(mapping.owasp_2021))
    if mapping.pci_dss_v4:
        parts.append("PCI " + ",".join(mapping.pci_dss_v4))
    if mapping.iso_27001:
        parts.append("ISO " + ",".join(mapping.iso_27001))
    if mapping.nist_csf:
        parts.append("NIST " + ",".join(mapping.nist_csf))
    if mapping.cis_v8:
        parts.append("CIS " + ",".join(mapping.cis_v8))
    if mapping.uu_pdp:
        parts.append("UU-PDP " + ",".join(mapping.uu_pdp))
    return " | ".join(parts)


def render_finding_detail(f: Finding, idx: int) -> None:
    console = get_console()
    style = SEV_STYLE[f.severity]
    score = score_finding(f)
    band = severity_band(score)
    header = Text.assemble(
        (f"[{f.severity.value.upper()}] ", style),
        (f"#{idx} {f.title}", "bold"),
        ("  ", ""),
        (f"(risk {score:.1f}/10 - {band})", "bold yellow"),
    )
    body_parts = [
        Text.assemble(("Module: ", "bold"), (f.module, "cyan")),
        Text.assemble(("Target: ", "bold"), (f.target, "cyan")),
    ]
    if f.cwe:
        body_parts.append(Text.assemble(("CWE   : ", "bold"), (f.cwe, "cyan")))
    compl = _compliance_one_liner(f)
    if compl:
        body_parts.append(
            Text.assemble(("Compliance: ", "bold"), (compl, "magenta"))
        )
    body_parts.append(Text(""))
    body_parts.append(Text.assemble(("Deskripsi:\n", "bold"), (f.description, "")))
    if f.evidence:
        body_parts.append(Text(""))
        body_parts.append(
            Text.assemble(("Evidence:\n", "bold"), (f.evidence, "yellow"))
        )
    if f.remediation:
        body_parts.append(Text(""))
        body_parts.append(
            Text.assemble(("Remediasi:\n", "bold"), (f.remediation, "green"))
        )
    if f.references:
        body_parts.append(Text(""))
        body_parts.append(
            Text.assemble(
                ("Referensi:\n", "bold"),
                ("\n".join("- " + r for r in f.references), "blue"),
            )
        )
    # Threat intelligence: penjelasan celah + cara hacker eksploitasi
    from cyberloka.core.threat_intel import get_threat_profile
    profile = get_threat_profile(f.module, f.cwe)
    if profile is not None:
        body_parts.append(Text(""))
        body_parts.append(
            Text.assemble(
                ("Apa itu kelemahan ini?\n", "bold magenta"),
                (profile.what_it_is, ""),
            )
        )
        body_parts.append(Text(""))
        body_parts.append(
            Text.assemble(
                ("Mengapa berbahaya?\n", "bold magenta"),
                (profile.why_dangerous, ""),
            )
        )
        if profile.attack_scenarios:
            body_parts.append(Text(""))
            body_parts.append(
                Text.assemble(
                    ("Cara hacker mengeksploitasi:\n", "bold red"),
                    ("\n".join("- " + s for s in profile.attack_scenarios[:3]), "yellow"),
                )
            )
        if profile.real_world_impact:
            body_parts.append(Text(""))
            body_parts.append(
                Text.assemble(
                    ("Dampak di dunia nyata:\n", "bold magenta"),
                    (profile.real_world_impact, "dim"),
                )
            )
    # Verification details (only present after a verify pass)
    v = (f.extra or {}).get("verification") if f.extra else None
    if v:
        body_parts.append(Text(""))
        status = v.get("status", "tentative")
        body_parts.append(
            Text.assemble(
                ("Verification: ", "bold"),
                (
                    status.upper().replace("_", " "),
                    _VSTATUS_STYLE.get(status, "dim"),
                ),
                ("  ", ""),
                (f"({v.get('verified_at', '')})", "dim"),
            )
        )
        attempts = v.get("attempts", []) or []
        if attempts:
            lines = []
            for a in attempts:
                marker = "[+]" if a.get("success") else "[-]"
                lines.append(
                    f"  {marker} {a.get('technique', '?')}: "
                    f"{a.get('detail', '') or a.get('payload', '')}"
                )
            body_parts.append(
                Text.assemble(
                    ("Attempts:\n", "bold"),
                    ("\n".join(lines), "yellow"),
                )
            )
        if v.get("poc"):
            body_parts.append(
                Text.assemble(("PoC:\n", "bold"), (v["poc"], "magenta"))
            )
    body = Text("\n").join(body_parts)
    console.print(Panel(body, title=header, border_style=style))


def render_summary(findings: list[Finding]) -> None:
    console = get_console()
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    table = Table(title="Ringkasan", expand=False)
    table.add_column("Severity")
    table.add_column("Jumlah", justify="right")
    for s in Severity:
        table.add_row(
            Text(s.value.upper(), style=SEV_STYLE[s]),
            str(counts[s]),
        )
    table.add_row(Text("TOTAL", style="bold"), str(len(findings)))
    console.print(table)


def render_module_stats(stats: list[dict]) -> None:
    """Render per-module execution stats — supaya jelas modul mana yang
    jalan, mana yang skip, dan berapa lama. User sering bingung saat
    finding sedikit padahal banyak modul yang dipilih.
    """
    console = get_console()
    if not stats:
        return
    table = Table(title="Module Execution", expand=True)
    table.add_column("Module", style="cyan", width=18)
    table.add_column("Status", width=10)
    table.add_column("Findings", justify="right", width=9)
    table.add_column("Duration", justify="right", width=10)
    table.add_column("Note", overflow="fold")

    status_styles = {
        "ok": "green",
        "error": "bold red",
        "skipped": "dim yellow",
    }

    for s in stats:
        status = s.get("status", "ok")
        findings = s.get("findings", 0)
        duration_ms = s.get("duration_ms", 0)
        note = s.get("error") or ""
        if status == "ok" and findings == 0:
            note = note or "(tidak ada finding -- target mungkin sudah aman)"
        table.add_row(
            s.get("module", "?"),
            Text(status.upper(), style=status_styles.get(status, "dim")),
            str(findings) if status == "ok" else "-",
            f"{duration_ms} ms" if duration_ms else "-",
            note,
        )
    console.print(table)


def render_executive_summary(findings: list[Finding]) -> None:
    """One-page management view with grade, score, and top 5 priorities."""
    console = get_console()
    summary = build_executive_summary(findings)

    grade_style = GRADE_STYLE.get(summary.grade, "bold")
    header = Text.assemble(
        ("Executive Summary  ", "bold"),
        (f"  Grade: ", ""),
        (f" {summary.grade} ", grade_style),
        ("  ", ""),
        (f"Score: {summary.overall_score:.1f}/100  ", "bold cyan"),
        (f"({summary.grade_label})", "dim"),
    )

    counts = summary.by_severity
    sev_line = (
        f"Critical {counts['critical']}  |  High {counts['high']}  |  "
        f"Medium {counts['medium']}  |  Low {counts['low']}  |  "
        f"Info {counts['info']}"
    )

    body_parts = [
        Text.assemble(("Postur:\n", "bold"), (summary.posture, "")),
        Text(""),
        Text.assemble(("Distribusi Risk: ", "bold"), (sev_line, "cyan")),
        Text.assemble(
            ("Total finding: ", "bold"),
            (f"{summary.total_findings} ", "cyan"),
            (f"({summary.actionable_findings} actionable)", "dim"),
        ),
    ]
    console.print(Panel(Text("\n").join(body_parts), title=header, border_style="magenta"))

    if summary.top_priorities:
        table = Table(title="Top 5 Prioritas Perbaikan", expand=True)
        table.add_column("#", width=3, style="dim")
        table.add_column("Risk", width=6, justify="right")
        table.add_column("Severity", width=10)
        table.add_column("Module", width=12)
        table.add_column("Issue", overflow="fold")
        for i, p in enumerate(summary.top_priorities, 1):
            sev = Severity(p["severity"])
            table.add_row(
                str(i),
                f"{p['score']:.1f}",
                Text(p["severity"].upper(), style=SEV_STYLE[sev]),
                p["module"],
                p["title"],
            )
        console.print(table)


def render_compliance_summary(findings: list[Finding]) -> None:
    """Render aggregate compliance mapping table (per framework)."""
    console = get_console()
    summary = compliance_summary(findings)
    framework_titles = {
        "owasp_2021": "OWASP Top 10 2021",
        "pci_dss_v4": "PCI-DSS v4.0",
        "iso_27001": "ISO/IEC 27001:2022",
        "nist_csf": "NIST CSF 2.0",
        "cis_v8": "CIS Controls v8",
        "uu_pdp": "UU PDP Indonesia (UU 27/2022)",
    }

    any_row = any(rows for rows in summary.values())
    if not any_row:
        return

    for fw_key, title in framework_titles.items():
        rows = summary.get(fw_key, [])
        if not rows:
            continue
        table = Table(title=title, expand=True)
        table.add_column("Clause", style="bold cyan", width=14)
        table.add_column("Findings", justify="right", width=9)
        table.add_column("Risk Weight", justify="right", width=11)
        table.add_column("Description", overflow="fold")
        for row in rows:
            table.add_row(
                row["id"],
                str(row["count"]),
                str(row["weight"]),
                row["label"],
            )
        console.print(table)



# ---------------------------------------------------------------------------
# Verification summary
# ---------------------------------------------------------------------------


def render_verification_summary(findings: list[Finding]) -> None:
    """Render a table of findings that have been re-tested (verified)."""
    console = get_console()
    rows: list[Finding] = [
        f for f in findings if f.extra and f.extra.get("verification")
    ]
    if not rows:
        return
    table = Table(title="Verification (Deep Re-Test)", expand=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Status", width=14)
    table.add_column("Severity", width=10)
    table.add_column("Module", width=12)
    table.add_column("Title", overflow="fold")
    table.add_column("Attempts", width=9, justify="right")

    rows.sort(key=lambda f: (f.severity.order, f.module))
    for i, f in enumerate(rows, 1):
        v = f.extra["verification"]
        status = v.get("status", "tentative")
        attempts = v.get("attempts", []) or []
        successes = sum(1 for a in attempts if a.get("success"))
        table.add_row(
            str(i),
            Text(status.upper().replace("_", " "), style=_VSTATUS_STYLE.get(status, "dim")),
            Text(f.severity.value.upper(), style=SEV_STYLE[f.severity]),
            f.module,
            f.title,
            f"{successes}/{len(attempts)}",
        )
    console.print(table)
