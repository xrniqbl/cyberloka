"""PDF report exporter (ReportLab).

Rendering rapi dengan:
- Word-wrap pada semua sel tabel (pakai Paragraph, bukan str biasa).
- Markup HTML mini (`<b>`, `<i>`, `<a href>`) ter-render sebagai gaya, BUKAN literal.
- Severity di-color, link biru di-underline, evidence/code di font monospace.
- Halaman A4 + header & footer berisi tool, target, timestamp, nomor halaman.
"""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from cyberloka import __version__
from cyberloka.core import Finding, Severity, Target
from cyberloka.core.config import ScanConfig

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
PAGE_W, PAGE_H = A4
MARGIN_X = 18 * mm
MARGIN_Y = 18 * mm

SEVERITY_COLOR = {
    Severity.CRITICAL: colors.HexColor("#7F1D1D"),
    Severity.HIGH: colors.HexColor("#B91C1C"),
    Severity.MEDIUM: colors.HexColor("#B45309"),
    Severity.LOW: colors.HexColor("#0E7490"),
    Severity.INFO: colors.HexColor("#475569"),
}
SEVERITY_BG = {
    Severity.CRITICAL: colors.HexColor("#FEE2E2"),
    Severity.HIGH: colors.HexColor("#FEE2E2"),
    Severity.MEDIUM: colors.HexColor("#FEF3C7"),
    Severity.LOW: colors.HexColor("#CFFAFE"),
    Severity.INFO: colors.HexColor("#E2E8F0"),
}
HEADER_BG = colors.HexColor("#1F2937")
ROW_ALT = colors.HexColor("#F8FAFC")
ACCENT = colors.HexColor("#1F77B4")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    out: dict[str, ParagraphStyle] = {}
    out["title"] = ParagraphStyle(
        "title",
        parent=base["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#111827"),
        alignment=TA_LEFT,
        spaceAfter=4,
    )
    out["subtitle"] = ParagraphStyle(
        "subtitle",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#4B5563"),
        alignment=TA_LEFT,
        spaceAfter=12,
    )
    out["h2"] = ParagraphStyle(
        "h2",
        parent=base["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#111827"),
        spaceBefore=10,
        spaceAfter=6,
    )
    out["h3"] = ParagraphStyle(
        "h3",
        parent=base["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#111827"),
        spaceBefore=6,
        spaceAfter=4,
    )
    out["body"] = ParagraphStyle(
        "body",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=12.5,
        textColor=colors.HexColor("#111827"),
        spaceAfter=2,
    )
    out["body_small"] = ParagraphStyle(
        "body_small",
        parent=out["body"],
        fontSize=8.5,
        leading=11,
    )
    out["mono"] = ParagraphStyle(
        "mono",
        parent=out["body"],
        fontName="Courier",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#1F2937"),
        backColor=colors.HexColor("#F3F4F6"),
        borderPadding=4,
        leftIndent=2,
        rightIndent=2,
    )
    out["th"] = ParagraphStyle(
        "th",
        parent=out["body"],
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=12,
        textColor=colors.white,
    )
    out["sev_pill"] = ParagraphStyle(
        "sev_pill",
        parent=out["body"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=10,
        alignment=1,
        textColor=colors.white,
    )
    out["link"] = ParagraphStyle(
        "link",
        parent=out["body"],
        textColor=ACCENT,
    )
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_ALLOWED_TAGS_RE = re.compile(
    r"</?(?:b|strong|i|em|u|br|font|a|sub|sup|para)(?:\s[^>]*)?/?>", re.I
)


def _safe_markup(text: str) -> str:
    """Escape HTML in ``text`` while keeping the small tag set ReportLab supports.

    This is what makes the PDF render `<b>`, links, and color tags correctly
    instead of showing them as literal text.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)

    # Save allowed tags with placeholders, escape everything else, then restore.
    placeholders: list[str] = []

    def _save(m: re.Match[str]) -> str:
        placeholders.append(m.group(0))
        return f"\x00TAG{len(placeholders) - 1}\x00"

    masked = _ALLOWED_TAGS_RE.sub(_save, text)
    escaped = html.escape(masked, quote=False)

    def _restore(m: re.Match[str]) -> str:
        i = int(m.group(1))
        return placeholders[i]

    safe = re.sub(r"\x00TAG(\d+)\x00", _restore, escaped)
    safe = safe.replace("\n", "<br/>")
    return safe


def _link(url: str) -> str:
    """Return a ReportLab-friendly underlined blue hyperlink."""
    safe = html.escape(url)
    return (
        f'<font color="#1F77B4"><a href="{safe}">'
        f"<u>{safe}</u></a></font>"
    )


def _autolink(text: str) -> str:
    """Convert raw URLs in already-escaped markup to clickable hyperlinks."""
    def repl(m: re.Match[str]) -> str:
        url = m.group(0)
        return _link(url)

    # Run on the unescaped form so we don't replace inside attributes
    return re.sub(r"https?://[^\s<>'\"]+", repl, text)


def _para(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_autolink(_safe_markup(text)), style)


def _severity_pill(sev: Severity, styles: dict[str, ParagraphStyle]) -> Table:
    label = sev.value.upper()
    p = Paragraph(label, styles["sev_pill"])
    t = Table([[p]], colWidths=[20 * mm], rowHeights=[6 * mm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_COLOR[sev]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("ROUNDEDCORNERS", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return t


def _summary_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    counts["total"] = len(findings)
    return counts


# ---------------------------------------------------------------------------
# Page chrome
# ---------------------------------------------------------------------------
class _ReportDoc(BaseDocTemplate):
    def __init__(self, filename: str, *, target_label: str, generated_at: str, **kw: Any):
        super().__init__(
            filename,
            pagesize=A4,
            leftMargin=MARGIN_X,
            rightMargin=MARGIN_X,
            topMargin=MARGIN_Y + 8 * mm,
            bottomMargin=MARGIN_Y + 6 * mm,
            title="Cyberloka Security Report",
            author="Cyberloka",
            **kw,
        )
        self.target_label = target_label
        self.generated_at = generated_at
        frame = Frame(
            self.leftMargin,
            self.bottomMargin,
            self.width,
            self.height,
            id="content",
            showBoundary=0,
        )
        self.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=self._chrome)])

    def _chrome(self, canvas, doc) -> None:  # noqa: ANN001
        canvas.saveState()

        # Header bar
        canvas.setFillColor(HEADER_BG)
        canvas.rect(0, PAGE_H - 14 * mm, PAGE_W, 14 * mm, stroke=0, fill=1)

        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 12)
        canvas.drawString(MARGIN_X, PAGE_H - 9 * mm, "Cyberloka Security Report")
        canvas.setFont("Helvetica", 9)
        canvas.drawRightString(
            PAGE_W - MARGIN_X,
            PAGE_H - 9 * mm,
            f"Target: {self.target_label}",
        )

        # Footer
        canvas.setFillColor(colors.HexColor("#6B7280"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(
            MARGIN_X, 10 * mm, f"Generated {self.generated_at}  -  cyberloka v{__version__}"
        )
        canvas.drawRightString(
            PAGE_W - MARGIN_X, 10 * mm, f"Page {doc.page}"
        )
        canvas.setStrokeColor(colors.HexColor("#E5E7EB"))
        canvas.line(MARGIN_X, 13 * mm, PAGE_W - MARGIN_X, 13 * mm)

        canvas.restoreState()


# ---------------------------------------------------------------------------
# Story builders
# ---------------------------------------------------------------------------
def _summary_table(findings: list[Finding], styles: dict[str, ParagraphStyle]) -> Table:
    counts = _summary_counts(findings)
    header = [
        Paragraph("Severity", styles["th"]),
        Paragraph("Total", styles["th"]),
    ]
    rows: list[list[Any]] = [header]
    for sev in Severity:
        rows.append(
            [
                _severity_pill(sev, styles),
                Paragraph(str(counts[sev.value]), styles["body"]),
            ]
        )
    rows.append(
        [
            Paragraph("<b>TOTAL</b>", styles["body"]),
            Paragraph(f"<b>{counts['total']}</b>", styles["body"]),
        ]
    )

    t = Table(rows, colWidths=[35 * mm, 25 * mm], hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#F1F5F9")),
            ]
        )
    )
    return t


def _findings_table(findings: list[Finding], styles: dict[str, ParagraphStyle]) -> Table:
    """Compact at-a-glance table.

    All cells are Paragraphs so they wrap and ALL HTML markup (`<b>`, links,
    `<font color>`) renders as styling, not as literal text.
    """
    header = [
        Paragraph("#", styles["th"]),
        Paragraph("Severity", styles["th"]),
        Paragraph("Module", styles["th"]),
        Paragraph("Title", styles["th"]),
        Paragraph("Target", styles["th"]),
    ]
    rows: list[list[Any]] = [header]
    body_style = styles["body_small"]
    for i, f in enumerate(findings, 1):
        rows.append(
            [
                Paragraph(str(i), body_style),
                _severity_pill(f.severity, styles),
                Paragraph(_safe_markup(f.module), body_style),
                Paragraph(_safe_markup(f.title), body_style),
                Paragraph(_autolink(_safe_markup(f.target)), body_style),
            ]
        )

    col_widths = [10 * mm, 22 * mm, 28 * mm, 70 * mm, 44 * mm]
    t = Table(rows, colWidths=col_widths, repeatRows=1, hAlign="LEFT")

    style_cmds: list[tuple[Any, ...]] = [
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    # zebra rows
    for r in range(2, len(rows), 2):
        style_cmds.append(("BACKGROUND", (0, r), (-1, r), ROW_ALT))
    t.setStyle(TableStyle(style_cmds))
    return t


def _finding_card(idx: int, f: Finding, styles: dict[str, ParagraphStyle]) -> KeepTogether:
    """Render one finding as a 'card': header bar + key/value body."""
    sev_color = SEVERITY_COLOR[f.severity]
    sev_bg = SEVERITY_BG[f.severity]

    title_html = (
        f'<font color="white" size="10"><b>'
        f'#{idx} &nbsp; {_safe_markup(f.title)}'
        f'</b></font>'
    )
    title_para = Paragraph(title_html, styles["body"])
    sev_para = Paragraph(
        f'<font color="white"><b>{f.severity.value.upper()}</b></font>',
        styles["body"],
    )
    head = Table(
        [[title_para, sev_para]],
        colWidths=[140 * mm, 34 * mm],
    )
    head.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), HEADER_BG),
                ("BACKGROUND", (1, 0), (1, 0), sev_color),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (1, 0), (1, 0), "CENTER"),
            ]
        )
    )

    rows: list[list[Any]] = []

    def kv(label: str, value: str, mono: bool = False) -> None:
        st = styles["mono"] if mono else styles["body"]
        rows.append(
            [
                Paragraph(f"<b>{label}</b>", styles["body"]),
                _para(value, st) if not mono else Paragraph(_safe_markup(value), st),
            ]
        )

    kv("Module", f.module)
    kv("Target", f.target)
    if f.cwe:
        kv("CWE", f.cwe)
    kv("Confidence", f.confidence)
    kv("Description", f.description)
    if f.evidence:
        kv("Evidence", f.evidence, mono=True)
    if f.remediation:
        kv("Remediation", f.remediation)
    if f.references:
        ref_html = "<br/>".join(f"&bull; {_link(r)}" for r in f.references)
        rows.append(
            [
                Paragraph("<b>References</b>", styles["body"]),
                Paragraph(ref_html, styles["body"]),
            ]
        )

    body = Table(rows, colWidths=[28 * mm, 146 * mm], hAlign="LEFT")
    body.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#E5E7EB")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
                ("BACKGROUND", (1, 0), (1, -1), colors.white),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    # subtle severity tint on the top border row
    if sev_bg is not None:
        pass

    spacer = Spacer(1, 4)
    return KeepTogether([head, body, spacer])


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------
def write_pdf(
    path: str,
    target: Target,
    config: ScanConfig,
    findings: list[Finding],
) -> None:
    """Render full PDF report to ``path``."""
    styles = _styles()
    findings_sorted = sorted(findings, key=lambda f: (f.severity.order, f.module))
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    doc = _ReportDoc(
        path,
        target_label=target.base_url,
        generated_at=generated_at,
    )

    story: list[Any] = []
    story.append(Paragraph("Security Assessment Report", styles["title"]))
    story.append(
        Paragraph(
            f"Tool: <b>cyberloka v{__version__}</b> &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"Generated: <b>{generated_at}</b>",
            styles["subtitle"],
        )
    )

    # Scope block
    scope_rows = [
        [Paragraph("<b>Target</b>", styles["body"]),
         Paragraph(_autolink(_safe_markup(target.base_url)), styles["body"])],
        [Paragraph("<b>Host</b>", styles["body"]),
         Paragraph(_safe_markup(f"{target.host}:{target.port}"), styles["body"])],
        [Paragraph("<b>Scheme</b>", styles["body"]),
         Paragraph(target.scheme.upper(), styles["body"])],
        [Paragraph("<b>Mode</b>", styles["body"]),
         Paragraph(_safe_markup(config.mode), styles["body"])],
        [Paragraph("<b>Modules</b>", styles["body"]),
         Paragraph(_safe_markup(", ".join(config.resolve_modules())), styles["body"])],
    ]
    scope_tbl = Table(scope_rows, colWidths=[28 * mm, 146 * mm], hAlign="LEFT")
    scope_tbl.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#E5E7EB")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(Paragraph("Scope", styles["h2"]))
    story.append(scope_tbl)

    # Summary
    story.append(Paragraph("Summary", styles["h2"]))
    story.append(_summary_table(findings_sorted, styles))

    if not findings_sorted:
        story.append(Spacer(1, 8))
        story.append(
            Paragraph(
                "<i>Tidak ada temuan terverifikasi pada scan ini.</i>",
                styles["body"],
            )
        )
        doc.build(story)
        return

    # Findings overview table
    story.append(Paragraph("Findings Overview", styles["h2"]))
    story.append(_findings_table(findings_sorted, styles))
    story.append(PageBreak())

    # Per-finding details
    story.append(Paragraph("Findings Detail", styles["h2"]))
    for i, f in enumerate(findings_sorted, 1):
        story.append(_finding_card(i, f, styles))

    doc.build(story)
