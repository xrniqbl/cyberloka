"""Rich console reporter."""
from __future__ import annotations

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cyberloka.core import Finding, Severity
from cyberloka.core.logger import get_console

SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "dim",
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
    console.print(Panel.fit(Text.assemble(title, "\n", sub, "\n\n", body), border_style="magenta"))


def render_findings(findings: list[Finding]) -> None:
    console = get_console()
    if not findings:
        console.print("[green]Tidak ada finding.[/green]")
        return

    findings_sorted = sorted(findings, key=lambda f: (f.severity.order, f.module))
    table = Table(title="Findings", show_lines=False, expand=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Module", width=14)
    table.add_column("Title", overflow="fold")
    for i, f in enumerate(findings_sorted, 1):
        table.add_row(
            str(i),
            Text(f.severity.value.upper(), style=SEV_STYLE[f.severity]),
            f.module,
            f.title,
        )
    console.print(table)


def render_finding_detail(f: Finding, idx: int) -> None:
    console = get_console()
    style = SEV_STYLE[f.severity]
    header = Text.assemble(
        (f"[{f.severity.value.upper()}] ", style),
        (f"#{idx} {f.title}", "bold"),
    )
    body_parts = [
        Text.assemble(("Module: ", "bold"), (f.module, "cyan")),
        Text.assemble(("Target: ", "bold"), (f.target, "cyan")),
    ]
    if f.cwe:
        body_parts.append(Text.assemble(("CWE   : ", "bold"), (f.cwe, "cyan")))
    body_parts.append(Text(""))
    body_parts.append(Text.assemble(("Deskripsi:\n", "bold"), (f.description, "")))
    if f.evidence:
        body_parts.append(Text(""))
        body_parts.append(Text.assemble(("Evidence:\n", "bold"), (f.evidence, "yellow")))
    if f.remediation:
        body_parts.append(Text(""))
        body_parts.append(Text.assemble(("Remediasi:\n", "bold"), (f.remediation, "green")))
    if f.references:
        body_parts.append(Text(""))
        body_parts.append(Text.assemble(("Referensi:\n", "bold"), ("\n".join("- " + r for r in f.references), "blue")))
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
