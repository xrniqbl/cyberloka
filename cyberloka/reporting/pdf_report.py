"""PDF report exporter.

Renders the unified report bundle as a professionally formatted PDF using
ReportLab. Includes a colored grade card, severity stats, top-5 priorities
table, compliance mapping per framework, and a detail card per finding
(with verification block when present).

ReportLab is an optional dependency. Install it via the `pdf` extra:

    pip install "cyberloka[pdf]"

If ReportLab is unavailable, callers receive a clear ImportError so they
can fall back to HTML/TXT.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cyberloka import __version__
from cyberloka.core import Finding, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.report_bundle import build_bundle


# ---------------------------------------------------------------------------
# Color palette (matches HTML report)
# ---------------------------------------------------------------------------

_PALETTE = {
    "bg":         "#FFFFFF",
    "text":       "#1a1d27",
    "muted":      "#6b7280",
    "border":     "#d1d5db",
    "surface":    "#f6f7f9",
    "accent":     "#8b5cf6",
    "critical":   "#ef4444",
    "high":       "#f97316",
    "medium":     "#eab308",
    "low":        "#38bdf8",
    "info":       "#6b7280",
    "ok":         "#10b981",
    "grade_a_plus": "#10b981",
    "grade_a":    "#22c55e",
    "grade_b":    "#06b6d4",
    "grade_c":    "#eab308",
    "grade_d":    "#f97316",
    "grade_f":    "#ef4444",
    "vfp":        "#9ca3af",
    "vconf":      "#10b981",
    "vfirm":      "#38bdf8",
    "vtent":      "#eab308",
}


_FW_TITLES = {
    "owasp_2021": "OWASP Top 10 2021",
    "pci_dss_v4": "PCI-DSS v4.0",
    "iso_27001":  "ISO/IEC 27001:2022",
    "nist_csf":   "NIST CSF 2.0",
    "cis_v8":     "CIS Controls v8",
    "uu_pdp":     "UU PDP Indonesia (UU 27/2022)",
}


def _grade_color(grade: str) -> str:
    return {
        "A+": _PALETTE["grade_a_plus"],
        "A":  _PALETTE["grade_a"],
        "B":  _PALETTE["grade_b"],
        "C":  _PALETTE["grade_c"],
        "D":  _PALETTE["grade_d"],
        "F":  _PALETTE["grade_f"],
    }.get(grade, _PALETTE["accent"])


def _verify_color(status: str) -> str:
    return {
        "confirmed":      _PALETTE["vconf"],
        "firm":           _PALETTE["vfirm"],
        "tentative":      _PALETTE["vtent"],
        "false_positive": _PALETTE["vfp"],
    }.get(status, _PALETTE["muted"])


def _sev_color(sev: str) -> str:
    return _PALETTE.get(sev, _PALETTE["info"])


def _check_reportlab() -> None:
    try:
        import reportlab  # noqa: F401
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "PDF export requires ReportLab. Install it with:\n"
            "    pip install 'cyberloka[pdf]'\n"
            "Alternatively, use --html or --txt for non-PDF reports."
        ) from e


def _escape(text: str) -> str:
    """Escape text for ReportLab Paragraph (XML-like)."""
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def write_pdf(
    path: str, target: Target, config: ScanConfig, findings: list[Finding]
) -> None:
    """Render the scan bundle to a PDF file at `path`."""
    _check_reportlab()

    # Imported here so importing this module without ReportLab installed
    # only fails when write_pdf() is actually called.
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        KeepTogether,
        PageTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    bundle = build_bundle(target, config, findings)
    es = bundle["executive_summary"]
    summary = bundle["summary"]
    counts = es["by_severity"]
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    Path(path).parent.mkdir(parents=True, exist_ok=True)

    # Doc + frame layout (with footer page numbers)
    doc = BaseDocTemplate(
        path,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"Cyberloka Report - {bundle['target'].get('host', '')}",
        author=f"Cyberloka {__version__}",
    )
    frame = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        doc.width,
        doc.height,
        id="body",
        showBoundary=0,
    )

    def _draw_footer(canvas, _doc):  # noqa: ARG001
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor(_PALETTE["muted"]))
        canvas.drawString(
            doc.leftMargin,
            10 * mm,
            f"Cyberloka {__version__}  |  {generated_at}",
        )
        canvas.drawRightString(
            A4[0] - doc.rightMargin,
            10 * mm,
            f"Page {_doc.page}",
        )
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="default", frames=[frame], onPage=_draw_footer)])

    styles = getSampleStyleSheet()
    base = ParagraphStyle(
        "Base",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor(_PALETTE["text"]),
        alignment=TA_LEFT,
    )
    h1 = ParagraphStyle("H1", parent=base, fontName="Helvetica-Bold", fontSize=18, leading=22)
    h2 = ParagraphStyle(
        "H2",
        parent=base,
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=18,
        textColor=colors.HexColor(_PALETTE["accent"]),
        spaceBefore=10,
        spaceAfter=6,
    )
    muted = ParagraphStyle(
        "Muted", parent=base, textColor=colors.HexColor(_PALETTE["muted"]), fontSize=9
    )
    code = ParagraphStyle(
        "Code",
        parent=base,
        fontName="Courier",
        fontSize=8.5,
        leading=11,
        backColor=colors.HexColor(_PALETTE["surface"]),
        borderColor=colors.HexColor(_PALETTE["border"]),
        borderWidth=0.5,
        borderPadding=4,
        textColor=colors.HexColor(_PALETTE["text"]),
    )
    label = ParagraphStyle(
        "Label",
        parent=base,
        fontName="Helvetica-Bold",
        fontSize=8.5,
        textColor=colors.HexColor(_PALETTE["muted"]),
        spaceBefore=4,
        spaceAfter=2,
    )

    story: list[Any] = []

    # ------------------------------------------------------------------
    # Header: grade card + meta
    # ------------------------------------------------------------------
    grade_color = _grade_color(es["grade"])
    grade_cell = Paragraph(
        f"<font size=42 color='white'><b>{es['grade']}</b></font><br/>"
        f"<font size=10 color='white'>{es['overall_score']:.1f} / 100</font>",
        ParagraphStyle("GradeCell", parent=base, alignment=1),
    )
    meta_text = (
        f"<font size=18><b>Cyberloka Security Report</b></font><br/>"
        f"<font color='{_PALETTE['muted']}'>{_escape(bundle['target'].get('base_url', ''))}</font><br/><br/>"
        f"<b>Mode:</b> {bundle['scan']['mode']}    "
        f"<b>Modules:</b> {len(bundle['scan']['modules'])}    "
        f"<b>Findings:</b> {summary['total']}<br/>"
        f"<b>Generated:</b> {generated_at}"
    )
    meta_cell = Paragraph(meta_text, base)
    header_table = Table(
        [[grade_cell, meta_cell]],
        colWidths=[36 * mm, doc.width - 36 * mm - 4 * mm],
    )
    header_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor(grade_color)),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (0, 0), 4),
            ("RIGHTPADDING", (0, 0), (0, 0), 4),
            ("TOPPADDING", (0, 0), (0, 0), 12),
            ("BOTTOMPADDING", (0, 0), (0, 0), 12),
            ("LEFTPADDING", (1, 0), (1, 0), 12),
            ("ROUNDEDCORNERS", [6, 6, 6, 6]),
            ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor(_PALETTE["border"])),
        ])
    )
    story.append(header_table)
    story.append(Spacer(1, 8))

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------
    story.append(Paragraph("Executive Summary", h2))
    story.append(Paragraph(_escape(es["posture"]), base))
    story.append(Spacer(1, 6))

    # Severity strip (5 colored cells)
    sev_cells = []
    for s in ("critical", "high", "medium", "low", "info"):
        cell = Paragraph(
            f"<font size=14><b>{counts[s]}</b></font><br/>"
            f"<font size=8>{s.upper()}</font>",
            ParagraphStyle(f"Sev_{s}", parent=base, alignment=1),
        )
        sev_cells.append(cell)
    sev_table = Table([sev_cells], colWidths=[doc.width / 5.0] * 5)
    sev_style = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor(_PALETTE["border"])),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor(_PALETTE["border"])),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]
    for i, s in enumerate(("critical", "high", "medium", "low", "info")):
        sev_style.append(
            ("TEXTCOLOR", (i, 0), (i, 0), colors.HexColor(_sev_color(s)))
        )
    sev_table.setStyle(TableStyle(sev_style))
    story.append(sev_table)

    vstats = summary.get("verification") or {}
    if vstats.get("verified"):
        story.append(Spacer(1, 4))
        story.append(
            Paragraph(
                f"<b>Verifikasi:</b> verified={vstats.get('verified', 0)}, "
                f"confirmed={vstats.get('confirmed', 0)}, "
                f"firm={vstats.get('firm', 0)}, "
                f"tentative={vstats.get('tentative', 0)}, "
                f"false_positive={vstats.get('false_positive', 0)}",
                muted,
            )
        )

    # ------------------------------------------------------------------
    # Top 5 priorities
    # ------------------------------------------------------------------
    if es.get("top_priorities"):
        story.append(Paragraph("Top 5 Prioritas Perbaikan", h2))
        rows = [["#", "Risk", "Severity", "Module", "Issue"]]
        body_rows: list[list] = []
        for i, p in enumerate(es["top_priorities"], 1):
            body_rows.append([
                str(i),
                f"{p['score']:.1f}",
                p["severity"].upper(),
                p["module"],
                Paragraph(_escape(p["title"]), base),
            ])
        rows.extend(body_rows)
        col_widths = [10 * mm, 14 * mm, 22 * mm, 28 * mm, doc.width - 74 * mm]
        t = Table(rows, colWidths=col_widths, repeatRows=1)
        ts = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(_PALETTE["surface"])),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (1, -1), "RIGHT"),
            ("ALIGN", (2, 0), (2, -1), "LEFT"),
            ("BOX", (0, 0), (-1, -1), 0.3, colors.HexColor(_PALETTE["border"])),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor(_PALETTE["border"])),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        for i, p in enumerate(es["top_priorities"], 1):
            ts.append(
                ("TEXTCOLOR", (2, i), (2, i), colors.HexColor(_sev_color(p["severity"])))
            )
        t.setStyle(TableStyle(ts))
        story.append(t)

    # ------------------------------------------------------------------
    # Compliance mapping
    # ------------------------------------------------------------------
    has_compl = any(rows for rows in bundle["compliance_summary"].values())
    if has_compl:
        story.append(Paragraph("Compliance Mapping", h2))
    else:
        story.append(Paragraph("Compliance Mapping", h2))
        story.append(Paragraph(
            "Tidak ada finding yang ter-map ke kontrol compliance.", muted))
    for fw, rows in bundle["compliance_summary"].items():
        if not rows:
            continue
        story.append(Spacer(1, 4))
        story.append(
            Paragraph(
                f"<b>{_FW_TITLES.get(fw, fw)}</b>",
                ParagraphStyle(
                    f"Fw_{fw}",
                    parent=base,
                    fontName="Helvetica-Bold",
                    fontSize=10,
                    textColor=colors.HexColor(_PALETTE["accent"]),
                ),
            )
        )
        rows_data = [["Clause", "Findings", "Weight", "Description"]]
        for r in rows:
            rows_data.append([
                r["id"],
                str(r["count"]),
                str(r["weight"]),
                Paragraph(_escape(r["label"]), base),
            ])
        col_widths = [30 * mm, 18 * mm, 18 * mm, doc.width - 66 * mm]
        t = Table(rows_data, colWidths=col_widths, repeatRows=1)
        t.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(_PALETTE["surface"])),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (1, 0), (2, -1), "RIGHT"),
                ("BOX", (0, 0), (-1, -1), 0.3, colors.HexColor(_PALETTE["border"])),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor(_PALETTE["border"])),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        story.append(KeepTogether(t))

    # ------------------------------------------------------------------
    # Findings detail
    # ------------------------------------------------------------------
    story.append(Paragraph(f"Findings ({len(bundle['findings'])})", h2))
    if not bundle["findings"]:
        story.append(Paragraph("Tidak ada finding.", muted))

    for i, f in enumerate(bundle["findings"], 1):
        sev = (f.get("severity") or "info").lower()
        sev_col = _sev_color(sev)

        # Title row: severity bar + finding header
        head_text = (
            f"<font color='{sev_col}'><b>[{sev.upper()}]</b></font>  "
            f"<font color='{_PALETTE['muted']}'>(risk {f.get('risk_score', 0.0):.1f}/10, "
            f"module: {f.get('module', '?')}{', CWE: ' + _escape(f['cwe']) if f.get('cwe') else ''})</font><br/>"
            f"<b>#{i:03d} {_escape(f.get('title', ''))}</b><br/>"
            f"<font size=8 color='{_PALETTE['muted']}'>{_escape(f.get('target', ''))}</font>"
        )
        body_blocks: list[Any] = [Paragraph(head_text, base)]

        if f.get("verification"):
            v = f["verification"]
            vc = _verify_color(v.get("status", "tentative"))
            body_blocks.append(
                Paragraph(
                    f"<font size=8 color='{vc}'><b>Verification:</b> "
                    f"{v.get('status', '?').upper().replace('_', ' ')}</font>",
                    base,
                )
            )

        body_blocks.append(Paragraph("Deskripsi", label))
        body_blocks.append(Paragraph(_escape(f.get("description", "")), base))

        if f.get("evidence"):
            body_blocks.append(Paragraph("Evidence", label))
            body_blocks.append(Paragraph(_escape(f["evidence"]), code))
        if f.get("remediation"):
            body_blocks.append(Paragraph("Remediasi", label))
            body_blocks.append(Paragraph(_escape(f["remediation"]), base))

        if f.get("compliance_tags"):
            tags = " &nbsp; ".join(
                f"<font color='{_PALETTE['muted']}'>{_escape(t)}</font>"
                for t in f["compliance_tags"]
            )
            body_blocks.append(Paragraph("Compliance", label))
            body_blocks.append(Paragraph(tags, base))

        if f.get("references"):
            body_blocks.append(Paragraph("Referensi", label))
            for r in f["references"]:
                body_blocks.append(
                    Paragraph(
                        f"&bull; <link href='{_escape(r)}' color='{_PALETTE['low']}'>{_escape(r)}</link>",
                        base,
                    )
                )

        if f.get("verification"):
            v = f["verification"]
            body_blocks.append(Paragraph("Verification Detail", label))
            if v.get("evidence_strong"):
                body_blocks.append(Paragraph(_escape(v["evidence_strong"]), base))
            for a in v.get("attempts") or []:
                marker = "[+]" if a.get("success") else "[-]"
                color = _PALETTE["ok"] if a.get("success") else _PALETTE["muted"]
                body_blocks.append(
                    Paragraph(
                        f"<font color='{color}'>{marker}</font> "
                        f"<font face='Courier' size=8>{_escape(a.get('technique', '?'))}</font> "
                        f"{_escape(a.get('detail', '') or a.get('payload', ''))}",
                        base,
                    )
                )
            if v.get("poc"):
                body_blocks.append(Paragraph("PoC", label))
                body_blocks.append(Paragraph(_escape(v["poc"]), code))

        # Wrap each finding in a colored-left-border table for visual grouping.
        finding_table = Table(
            [[body_blocks]],
            colWidths=[doc.width],
        )
        finding_table.setStyle(
            TableStyle([
                ("LINEBEFORE", (0, 0), (0, 0), 3, colors.HexColor(sev_col)),
                ("BOX", (0, 0), (-1, -1), 0.3, colors.HexColor(_PALETTE["border"])),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )
        story.append(KeepTogether([Spacer(1, 6), finding_table]))

    doc.build(story)
