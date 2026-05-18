"""PDF report exporter (Bahasa Indonesia, ReportLab).

Output:
  - Cover page (target, mode, ringkasan severity, tanggal).
  - Daftar isi.
  - Bab 1 Ringkasan Eksekutif + grafik batang severity + risk score.
  - Bab 2 Flowchart "Alur Serangan Tipikal".
  - Bab 3 Akses Yang Dapat / Berhasil Ditembus (penjelasan per-akses).
  - Bab 4 Detail Temuan (per-finding):
        * Apa Celahnya
        * Dampak Bisnis
        * Bukti / Evidence
        * Link Bug / Endpoint Terkait (clickable)
        * Cara Menanggulangi
        * Referensi
  - Bab 5 Rekomendasi Strategis & Roadmap Hardening.
  - Bab 6 Daftar Link Bug & Endpoint Bermasalah.
  - Lampiran A: Modul yang dijalankan.
  - Lampiran B: Glossary istilah keamanan.

Auto-naming: jika `path` tidak diberikan, file disimpan sebagai
`cyberloka-report-<host>-<timestamp>.pdf` di working directory.

Note: PDF reporter ini mengambil teks penjelasan dari
`cyberloka.reporting.explainer.EXPLAIN` (kamus modul -> friendly_name /
what_it_means / business_impact) dan `GLOSSARY` di file yang sama,
sehingga konten berbahasa Indonesia tetap konsisten dengan HTML report.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from reportlab.graphics.shapes import (
    Drawing,
    Polygon,
    Rect,
    String,
)
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)

from cyberloka import __version__
from cyberloka.core import Finding, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.explainer import EXPLAIN, GLOSSARY
from cyberloka.reporting.extras import MITRE_MAP, OWASP_MAP, REPRO_MAP
from cyberloka.reporting.scenarios import ACCESS_GAINED_MAP, is_access_gained

# ----------------------------- color palette -----------------------------

SEV_COLOR = {
    Severity.CRITICAL: colors.HexColor("#7B1F1F"),
    Severity.HIGH: colors.HexColor("#C0392B"),
    Severity.MEDIUM: colors.HexColor("#D4A017"),
    Severity.LOW: colors.HexColor("#1F77B4"),
    Severity.INFO: colors.HexColor("#7F8C8D"),
}
SEV_BG = {
    Severity.CRITICAL: colors.HexColor("#F5D6D6"),
    Severity.HIGH: colors.HexColor("#FADBD8"),
    Severity.MEDIUM: colors.HexColor("#FCF3CF"),
    Severity.LOW: colors.HexColor("#D6EAF8"),
    Severity.INFO: colors.HexColor("#ECF0F1"),
}
SEV_LABEL_ID = {
    Severity.CRITICAL: "KRITIS",
    Severity.HIGH: "TINGGI",
    Severity.MEDIUM: "SEDANG",
    Severity.LOW: "RENDAH",
    Severity.INFO: "INFO",
}

PRIMARY = colors.HexColor("#1F2A44")
ACCENT = colors.HexColor("#C0392B")

# ------------------------------ utilities --------------------------------


def _slug_host(target: Target) -> str:
    h = target.host or "target"
    h = re.sub(r"[^a-zA-Z0-9._-]+", "_", h)
    return h.strip("._-") or "target"


def auto_pdf_path(target: Target, out_dir: str | None = None) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"cyberloka-report-{_slug_host(target)}-{ts}.pdf"
    base = Path(out_dir) if out_dir else Path.cwd()
    base.mkdir(parents=True, exist_ok=True)
    return str(base / name)


_ALLOWED_TAGS_RE = re.compile(
    r"</?(?:b|strong|i|em|u|br|font|a|link|sub|sup|para|para[^>]*)(?:\s[^>]*)?/?>",
    re.I,
)


def _para(text: str, style) -> Paragraph:
    """Render ``text`` as a Paragraph.

    Whitelist a small set of HTML-ish tags supported by ReportLab Paragraph
    (``<b>``, ``<i>``, ``<u>``, ``<br/>``, ``<font color>``, ``<a href>``,
    ``<link href>``, ``<sub>``, ``<sup>``). Everything else - including any
    user-supplied ``<script>``, raw ``<`` / ``>`` / ``&`` - is escaped.

    Bug yang diperbaiki: sebelumnya semua ``<`` / ``>`` / ``&`` di-escape,
    sehingga markup yang sengaja kami bangun (``<b>...</b>``,
    ``<link href="...">``, ``<font color="...">``) muncul sebagai teks
    literal di laporan PDF.
    """
    if text is None:
        return Paragraph("", style)
    if not isinstance(text, str):
        text = str(text)

    # 1. Replace allowed tags with sentinels so we don't escape them.
    placeholders: list[str] = []

    def _save(m: "re.Match[str]") -> str:
        placeholders.append(m.group(0))
        return f"\x00TAG{len(placeholders) - 1}\x00"

    masked = _ALLOWED_TAGS_RE.sub(_save, text)

    # 2. Escape everything else (no quote=True so attribute values aren't broken
    #    when we later restore the tag exactly as the caller wrote it).
    masked = masked.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # 3. Restore the original tags untouched.
    def _restore(m: "re.Match[str]") -> str:
        return placeholders[int(m.group(1))]

    safe = re.sub(r"\x00TAG(\d+)\x00", _restore, masked)
    return Paragraph(safe, style)


def _styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("Title", parent=base["Title"], fontName="Helvetica-Bold",
                                fontSize=24, leading=30, alignment=TA_CENTER,
                                textColor=PRIMARY, spaceAfter=10),
        "subtitle": ParagraphStyle("Subtitle", parent=base["Normal"], fontName="Helvetica",
                                   fontSize=12, leading=16, alignment=TA_CENTER,
                                   textColor=colors.HexColor("#34495E"), spaceAfter=8),
        "h1": ParagraphStyle("H1", parent=base["Heading1"], fontName="Helvetica-Bold",
                             fontSize=18, leading=22, textColor=PRIMARY,
                             spaceBefore=14, spaceAfter=10),
        "h2": ParagraphStyle("H2", parent=base["Heading2"], fontName="Helvetica-Bold",
                             fontSize=13, leading=17, textColor=PRIMARY,
                             spaceBefore=10, spaceAfter=6),
        "h3": ParagraphStyle("H3", parent=base["Heading3"], fontName="Helvetica-Bold",
                             fontSize=11, leading=14, textColor=PRIMARY,
                             spaceBefore=8, spaceAfter=4),
        "body": ParagraphStyle("Body", parent=base["BodyText"], fontName="Helvetica",
                               fontSize=10, leading=14, alignment=TA_JUSTIFY, spaceAfter=6),
        "muted": ParagraphStyle("Muted", parent=base["BodyText"], fontName="Helvetica-Oblique",
                                fontSize=9, leading=12, textColor=colors.HexColor("#7F8C8D")),
        "evidence": ParagraphStyle("Evidence", parent=base["Code"], fontName="Courier",
                                   fontSize=8.5, leading=11,
                                   backColor=colors.HexColor("#F4F6F7"),
                                   borderColor=colors.HexColor("#D5D8DC"),
                                   borderWidth=0.5, borderPadding=6, spaceAfter=6),
        "kv_key": ParagraphStyle("KvKey", parent=base["Normal"], fontName="Helvetica-Bold",
                                 fontSize=10, leading=13, alignment=TA_LEFT, textColor=PRIMARY),
        "kv_val": ParagraphStyle("KvVal", parent=base["Normal"], fontName="Helvetica",
                                 fontSize=10, leading=13, alignment=TA_LEFT),
        "ethics": ParagraphStyle("Ethics", parent=base["Italic"], fontName="Helvetica-Oblique",
                                 fontSize=9, leading=12, alignment=TA_JUSTIFY,
                                 textColor=colors.HexColor("#7B1F1F"),
                                 backColor=colors.HexColor("#FCEFEF"), borderPadding=8),
    }


def _on_page(canvas, doc, target_label: str, version: str):
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(PRIMARY)
    canvas.rect(0, height - 12 * mm, width, 12 * mm, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(15 * mm, height - 8 * mm,
                      "CYBERLOKA  -  Laporan Pengujian Keamanan Web")
    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(width - 15 * mm, height - 8 * mm, target_label)
    canvas.setFillColor(colors.HexColor("#7F8C8D"))
    canvas.setFont("Helvetica", 8)
    canvas.drawString(15 * mm, 10 * mm,
                      f"Cyberloka v{version}  |  RAHASIA - hanya untuk pemilik target")
    canvas.drawRightString(width - 15 * mm, 10 * mm, f"Hal. {doc.page}")
    canvas.restoreState()


def _on_cover(canvas, doc):  # noqa: ARG001
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(PRIMARY)
    canvas.rect(0, height - 5 * cm, width, 5 * cm, stroke=0, fill=1)
    canvas.setFillColor(ACCENT)
    canvas.rect(0, 0, width, 1.5 * cm, stroke=0, fill=1)
    canvas.restoreState()


def _severity_chart(counts: dict[Severity, int]) -> Drawing:
    width, height = 16 * cm, 6 * cm
    d = Drawing(width, height)
    rows = [(s, SEV_LABEL_ID[s]) for s in Severity]
    max_val = max(1, max(counts.values()) if counts else 1)
    bar_max = width - 5 * cm
    bar_h = (height - 1.0 * cm) / len(rows) - 0.2 * cm
    y = height - 0.6 * cm
    for sev, label in rows:
        y -= bar_h + 0.2 * cm
        d.add(String(0, y + bar_h / 2 - 4, label, fontName="Helvetica-Bold", fontSize=9))
        d.add(Rect(3 * cm, y, bar_max, bar_h, fillColor=colors.HexColor("#ECF0F1"),
                   strokeColor=colors.HexColor("#BDC3C7"), strokeWidth=0.4))
        n = counts.get(sev, 0)
        w = (n / max_val) * bar_max if max_val else 0
        if w > 0:
            d.add(Rect(3 * cm, y, w, bar_h, fillColor=SEV_COLOR[sev], strokeColor=None))
        d.add(String(3 * cm + bar_max + 0.2 * cm, y + bar_h / 2 - 4, str(n),
                     fontName="Helvetica-Bold", fontSize=10, fillColor=PRIMARY))
    return d


def _attack_flowchart(target_label: str, modules: list[str]) -> Drawing:
    width, height = 17 * cm, 9 * cm
    d = Drawing(width, height)
    d.add(String(width / 2, height - 12,
                 "Alur Serangan Tipikal terhadap Aplikasi Web",
                 fontName="Helvetica-Bold", fontSize=11, fillColor=PRIMARY,
                 textAnchor="middle"))
    boxes = [
        ("1. Recon", ["DNS, WHOIS,", "subdomain,", "fingerprint, WAF"], colors.HexColor("#5DADE2")),
        ("2. Probe", ["headers, TLS,", "API/Swagger,", "GraphQL, robots"], colors.HexColor("#48C9B0")),
        ("3. Exploit", ["SQLi, XSS, SSRF,", "JWT, CSRF,", "secret leak"], colors.HexColor("#F5B041")),
        ("4. Post-Exploit", ["Session theft,", "lateral movement,", "data exfil"], colors.HexColor("#EC7063")),
        ("5. Impact", ["Data breach,", "RCE, fraud,", "reputation loss"], colors.HexColor("#7B1F1F")),
    ]
    box_w = (width - 2 * cm) / len(boxes) - 0.4 * cm
    box_h = 4.0 * cm
    y = height - box_h - 1.7 * cm
    x = 1 * cm
    centers = []
    for title, lines, fill in boxes:
        d.add(Rect(x, y, box_w, box_h, fillColor=fill, strokeColor=PRIMARY,
                   strokeWidth=0.7, rx=6, ry=6))
        d.add(String(x + box_w / 2, y + box_h - 16, title,
                     fontName="Helvetica-Bold", fontSize=10,
                     fillColor=colors.white, textAnchor="middle"))
        cy = y + box_h - 36
        for line in lines:
            d.add(String(x + box_w / 2, cy, line, fontName="Helvetica", fontSize=8,
                         fillColor=colors.white, textAnchor="middle"))
            cy -= 11
        centers.append((x + box_w, y + box_h / 2))
        x += box_w + 0.4 * cm
    for i, (x1, y1) in enumerate(centers[:-1]):
        x2 = centers[i + 1][0] - box_w
        d.add(Polygon(points=[x1, y1 - 3, x2 - 4, y1 - 3, x2 - 4, y1 - 8,
                              x2 + 6, y1, x2 - 4, y1 + 8, x2 - 4, y1 + 3,
                              x1, y1 + 3],
                      fillColor=PRIMARY, strokeColor=PRIMARY, strokeWidth=0.4))
    d.add(String(width / 2, 10,
                 f"Target: {target_label}  |  Modul aktif: {len(modules)}",
                 fontName="Helvetica-Oblique", fontSize=8,
                 fillColor=colors.HexColor("#7F8C8D"), textAnchor="middle"))
    return d


def _summary_counts(findings: list[Finding]) -> dict[Severity, int]:
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _kv_table(rows, styles) -> Table:
    data = [[_para(k, styles["kv_key"]), _para(v or "-", styles["kv_val"])] for k, v in rows]
    t = Table(data, colWidths=[4.5 * cm, 12 * cm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F4F6F7")),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5D8DC")),
    ]))
    return t


def _severity_pill(sev: Severity, styles) -> Table:
    p = Paragraph(f"<font color='white'><b>{SEV_LABEL_ID[sev]}</b></font>", styles["body"])
    t = Table([[p]], colWidths=[2.4 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SEV_COLOR[sev]),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


def _findings_overview_table(findings: list[Finding], styles) -> Table:
    data = [[_para("<b>#</b>", styles["body"]),
             _para("<b>Severity</b>", styles["body"]),
             _para("<b>Modul</b>", styles["body"]),
             _para("<b>Judul</b>", styles["body"])]]
    for i, f in enumerate(findings, 1):
        data.append([_para(str(i), styles["body"]),
                     _severity_pill(f.severity, styles),
                     _para(f.module, styles["body"]),
                     _para(f.title, styles["body"])])
    t = Table(data, colWidths=[1.0 * cm, 2.6 * cm, 3.0 * cm, 10.0 * cm],
              repeatRows=1, hAlign="LEFT")
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5D8DC")),
    ]
    for i, f in enumerate(findings, 1):
        style_cmds.append(("BACKGROUND", (0, i), (0, i), SEV_BG[f.severity]))
    t.setStyle(TableStyle(style_cmds))
    return t


# ----------------------------- main builder ------------------------------


def _build(doc_path: str, target: Target, config: ScanConfig, findings: list[Finding]):
    styles = _styles()
    findings_sorted = sorted(findings, key=lambda f: (f.severity.order, f.module, f.title))
    counts = _summary_counts(findings_sorted)
    target_label = target.base_url

    doc = BaseDocTemplate(
        doc_path, pagesize=A4,
        leftMargin=2.0 * cm, rightMargin=2.0 * cm,
        topMargin=2.2 * cm, bottomMargin=1.8 * cm,
        title=f"Cyberloka Report - {target.host}",
        author="Cyberloka",
        subject="Laporan Pengujian Keamanan Web",
    )
    cover_frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height,
                        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
                        id="cover")
    body_frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height,
                       leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
                       id="body")
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame], onPage=_on_cover),
        PageTemplate(id="body", frames=[body_frame],
                     onPage=lambda c, d: _on_page(c, d, target_label, __version__)),
    ])

    story: list = []

    # ============================ COVER ===================================
    story.append(Spacer(1, 1.0 * cm))
    story.append(_para("<font color='white'><b>LAPORAN PENGUJIAN<br/>KEAMANAN WEB</b></font>",
                       styles["title"]))
    story.append(Spacer(1, 0.3 * cm))
    story.append(_para("<font color='white'>Penilaian Kerentanan & Rekomendasi Perbaikan</font>",
                       styles["subtitle"]))
    story.append(Spacer(1, 2.5 * cm))

    cover_rows = [
        ("Target", target_label),
        ("Host", target.host),
        ("Mode Scan", config.mode.upper()),
        ("Modul Dijalankan", str(len(config.resolve_modules()))),
        ("Tanggal", datetime.now().strftime("%d %B %Y, %H:%M:%S")),
        ("Tool", f"Cyberloka v{__version__}"),
        ("Total Temuan", str(len(findings_sorted))),
        ("Severity Tertinggi",
         SEV_LABEL_ID[findings_sorted[0].severity] if findings_sorted else "-"),
    ]
    story.append(_kv_table(cover_rows, styles))
    story.append(Spacer(1, 1.0 * cm))
    story.append(_para(
        "<b>RAHASIA.</b> Dokumen ini berisi informasi sensitif tentang konfigurasi keamanan "
        "target. Sebarkan hanya kepada pihak yang berhak (pemilik aset & tim keamanan). "
        "Penggunaan tool dan laporan ini tunduk pada izin tertulis dari pemilik aset; "
        "penggunaan tanpa izin dapat melanggar UU ITE / hukum yang berlaku.",
        styles["ethics"],
    ))
    story.append(NextPageTemplate("body"))
    story.append(PageBreak())

    # =========================== DAFTAR ISI ===============================
    story.append(_para("Daftar Isi", styles["h1"]))
    toc_rows = [
        ("1.", "Ringkasan Eksekutif"),
        ("2.", "Alur Serangan Tipikal (Flowchart)"),
        ("3.", "Akses Yang Dapat / Berhasil Ditembus"),
        ("4.", "Detail Temuan"),
        ("5.", "Rekomendasi Strategis & Roadmap"),
        ("6.", "Daftar Link Bug & Endpoint Bermasalah"),
        ("A.", "Lampiran - Modul yang Dijalankan"),
        ("B.", "Lampiran - Glossary Istilah Keamanan"),
    ]
    toc_data = [[_para(f"<b>{a}</b>", styles["body"]), _para(b, styles["body"])]
                for a, b in toc_rows]
    t = Table(toc_data, colWidths=[1.5 * cm, 14 * cm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5D8DC")),
    ]))
    story.append(t)
    story.append(PageBreak())

    # ===================== 1. RINGKASAN EKSEKUTIF =========================
    story.append(_para("1. Ringkasan Eksekutif", styles["h1"]))
    story.append(_para(
        f"Pengujian keamanan dilakukan terhadap target <b>{target_label}</b> menggunakan "
        f"profil <b>{config.mode.upper()}</b> dan <b>{len(config.resolve_modules())} modul</b>. "
        f"Total <b>{len(findings_sorted)} temuan</b> ditemukan dengan distribusi sebagai berikut:",
        styles["body"],
    ))
    story.append(_severity_chart(counts))
    story.append(Spacer(1, 0.4 * cm))

    sev_rows = [[_para("<b>Severity</b>", styles["body"]),
                 _para("<b>Jumlah</b>", styles["body"]),
                 _para("<b>Arti</b>", styles["body"])]]
    sev_meaning = {
        Severity.CRITICAL: "Eksploitasi mudah & dampak besar. Perbaiki segera.",
        Severity.HIGH: "Risiko tinggi. Perbaiki dalam waktu dekat.",
        Severity.MEDIUM: "Penting. Masuk siklus rilis berikutnya.",
        Severity.LOW: "Best-practice / hardening.",
        Severity.INFO: "Informasi (tidak selalu kerentanan).",
    }
    for s in Severity:
        sev_rows.append([_severity_pill(s, styles),
                         _para(str(counts[s]), styles["body"]),
                         _para(sev_meaning[s], styles["body"])])
    sev_table = Table(sev_rows, colWidths=[2.6 * cm, 1.6 * cm, 12.4 * cm], hAlign="LEFT")
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5D8DC")),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 0.5 * cm))

    if findings_sorted:
        story.append(_para("Lima Temuan Paling Krusial", styles["h2"]))
        story.append(_findings_overview_table(findings_sorted[:5], styles))

    # =================== 2. FLOWCHART =====================================
    story.append(PageBreak())
    story.append(_para("2. Alur Serangan Tipikal", styles["h1"]))
    story.append(_para(
        "Diagram berikut menggambarkan tahapan umum yang dijalankan penyerang ketika "
        "menargetkan aplikasi web. Cyberloka memetakan tiap tahapan ke modul yang "
        "dijalankan, sehingga Anda dapat melihat di tahap mana pertahanan harus diperkuat.",
        styles["body"],
    ))
    story.append(_attack_flowchart(target_label, config.resolve_modules()))
    story.append(_para(
        "<b>Catatan:</b> Tidak setiap penyerang melalui semua tahap. Kerentanan kritis "
        "(mis. <i>secret bocor</i>, <i>SSRF ke metadata</i>, <i>SQL injection</i>) "
        "memungkinkan penyerang melompat langsung ke <b>tahap 4-5</b>.",
        styles["muted"],
    ))

    # =================== 3. AKSES YANG TERTEMBUS ==========================
    story.append(PageBreak())
    story.append(_para("3. Akses Yang Dapat / Berhasil Ditembus", styles["h1"]))
    accesses: list[tuple[Finding, str]] = []
    for f in findings_sorted:
        gained, label = is_access_gained(f)
        if gained:
            accesses.append((f, label))

    if not accesses:
        story.append(_para(
            "Tidak ada finding yang menandai bahwa attacker memperoleh akses signifikan. "
            "Tetap perhatikan finding severity rendah/sedang sebagai bagian dari hardening.",
            styles["body"],
        ))
    else:
        story.append(_para(
            "Bagian ini merangkum jenis akses yang <b>secara teknis dapat dicapai</b> "
            "berdasarkan finding pengujian. Setiap akses dipetakan ke temuan spesifik "
            "(beserta endpoint / parameter yang ter-tested).",
            styles["body"],
        ))
        grouped: dict[str, list[Finding]] = {}
        for f, label in accesses:
            grouped.setdefault(label, []).append(f)
        for label, items in grouped.items():
            story.append(_para(f"&#9658; {label}", styles["h2"]))
            data = [[_para("<b>Severity</b>", styles["body"]),
                     _para("<b>Modul</b>", styles["body"]),
                     _para("<b>Endpoint / Bukti</b>", styles["body"])]]
            for f in items:
                ev = (f.evidence or "-").splitlines()[0][:140] if f.evidence else "-"
                data.append([_severity_pill(f.severity, styles),
                             _para(f.module, styles["body"]),
                             _para(f"{f.target}<br/><font size='8' color='#7F8C8D'>{ev}</font>",
                                   styles["body"])])
            t = Table(data, colWidths=[2.6 * cm, 3.0 * cm, 11 * cm], hAlign="LEFT")
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5D8DC")),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.3 * cm))

    # ====================== 4. DETAIL TEMUAN ==============================
    story.append(PageBreak())
    story.append(_para("4. Detail Temuan", styles["h1"]))
    story.append(_para(
        "Setiap temuan dijelaskan dengan: <b>Apa Celahnya</b> "
        "(akar masalah teknis, dari modul scanner), <b>Dampak Bisnis</b> "
        "(arti dalam bahasa sehari-hari), <b>Bukti</b> (dari hasil scan), "
        "<b>Link Bug</b> (clickable), dan <b>Cara Menanggulangi</b>.",
        styles["body"],
    ))
    story.append(Spacer(1, 0.3 * cm))
    story.append(_findings_overview_table(findings_sorted, styles))

    for i, f in enumerate(findings_sorted, 1):
        story.append(PageBreak())
        story.append(_para(f"4.{i} {f.title}", styles["h2"]))

        info = EXPLAIN.get(f.module.lower(), {})

        meta_rows = [
            ("Severity", SEV_LABEL_ID[f.severity]),
            ("Modul", f.module),
            ("Target", f.target),
            ("Confidence", f.confidence),
        ]
        if f.cwe:
            meta_rows.append(("CWE", f.cwe))
        # OWASP Top 10: prefer module-level mapping, fallback to CWE-derived
        owasp_cat = OWASP_MAP.get(f.module.lower()) or f.owasp_category
        if owasp_cat:
            meta_rows.append(("OWASP Top 10", owasp_cat))
        # MITRE ATT&CK technique per modul
        mitre = MITRE_MAP.get(f.module.lower())
        if mitre:
            meta_rows.append(("MITRE ATT&CK", mitre))
        if f.bug_id:
            meta_rows.append(("Bug ID", f.bug_id))
        meta_rows.append(("Risk Score", f"{f.risk_score} / 100"))
        meta_rows.append(("Terdeteksi", f.detected_at))
        story.append(_kv_table(meta_rows, styles))
        story.append(Spacer(1, 0.2 * cm))

        story.append(_para("Apa Celahnya", styles["h3"]))
        what = info.get("what_it_means") or f.description or ""
        story.append(_para(what, styles["body"]))
        if f.description and what != f.description:
            story.append(_para(f.description, styles["body"]))

        impact = info.get("business_impact")
        if impact:
            story.append(_para("Dampak Bisnis", styles["h3"]))
            story.append(_para(impact, styles["body"]))

        if f.evidence:
            story.append(_para("Bukti / Evidence", styles["h3"]))
            story.append(Preformatted(f.evidence, styles["evidence"]))

        if f.urls:
            story.append(_para("Link Bug / Endpoint Terkait", styles["h3"]))
            for u in f.urls:
                disp = u if len(u) <= 100 else u[:97] + "..."
                story.append(_para(
                    f'&#8226; <link href="{u}"><font color="#1F77B4">{disp}</font></link>',
                    styles["body"],
                ))
            story.append(_para(
                "Catatan: Klik link di atas untuk verifikasi langsung di browser. "
                "Untuk endpoint yang memerlukan autentikasi, login terlebih dahulu "
                "ke aplikasi sebelum membuka link.",
                styles["muted"],
            ))

        story.append(_para("Cara Menanggulangi", styles["h3"]))
        story.append(_para(f.remediation or "Lihat referensi di bawah.", styles["body"]))

        # Cara Reproduksi (manual) - perintah curl/dig/openssl siap copy-paste
        repro_template = REPRO_MAP.get(f.module.lower(), "")
        if repro_template:
            url_for_repro = (f.urls[0] if f.urls else target.base_url)
            try:
                repro_text = repro_template.format(url=url_for_repro, host=target.host)
            except (KeyError, IndexError, ValueError):
                repro_text = repro_template
            story.append(_para("Cara Reproduksi (Manual)", styles["h3"]))
            story.append(Preformatted(repro_text, styles["evidence"]))

        if f.references:
            story.append(_para("Referensi", styles["h3"]))
            for r in f.references:
                story.append(_para(
                    f'&#8226; <link href="{r}"><font color="#1F77B4">{r}</font></link>',
                    styles["body"],
                ))

    # =================== 5. REKOMENDASI STRATEGIS =========================
    story.append(PageBreak())
    story.append(_para("5. Rekomendasi Strategis & Roadmap", styles["h1"]))
    rec_rows = [[_para("<b>Prioritas</b>", styles["body"]),
                 _para("<b>Tindakan</b>", styles["body"]),
                 _para("<b>Target Waktu</b>", styles["body"])]]
    plan = []
    if counts[Severity.CRITICAL]:
        plan.append(("KRITIS",
                     "Perbaiki temuan KRITIS (rotate secret, hapus management console publik, "
                     "tutup SSRF/SQLi/RCE, hapus subdomain takeover).",
                     "<= 24-72 jam"))
    if counts[Severity.HIGH]:
        plan.append(("TINGGI",
                     "Patch temuan TINGGI (XSS, JWT lemah, host-header injection, secret HMAC, "
                     "API documentation publik).", "<= 1-2 minggu"))
    if counts[Severity.MEDIUM]:
        plan.append(("SEDANG",
                     "Perkuat security headers (CSP, HSTS), CSRF token, cache-control, "
                     "mixed-content, info disclosure.", "<= 1 bulan"))
    plan.extend([
        ("HARDENING",
         "Aktifkan WAF & rate-limit di edge. Audit DNS rutin. Patching OS/library. "
         "Centralized logging + alert.", "<= 1-3 bulan"),
        ("PROSES",
         "Wajibkan SSDLC: review kode security, secret scanning di CI, dependency check, "
         "pen-test berkala, awareness training tim.", "Berkelanjutan"),
    ])
    for prio, action, eta in plan:
        rec_rows.append([_para(f"<b>{prio}</b>", styles["body"]),
                         _para(action, styles["body"]),
                         _para(eta, styles["body"])])
    rec_table = Table(rec_rows, colWidths=[3 * cm, 10.5 * cm, 3.0 * cm], hAlign="LEFT")
    rec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5D8DC")),
    ]))
    story.append(rec_table)

    # =================== 6. DAFTAR LINK BUG ===============================
    story.append(PageBreak())
    story.append(_para("6. Daftar Link Bug & Endpoint Bermasalah", styles["h1"]))
    story.append(_para(
        "Bagian ini merangkum seluruh URL/endpoint yang menjadi bukti temuan agar "
        "tim development dapat memverifikasi langsung. URL diurutkan dari severity "
        "tertinggi.",
        styles["body"],
    ))

    bug_rows = [[_para("<b>#</b>", styles["body"]),
                 _para("<b>Severity</b>", styles["body"]),
                 _para("<b>Modul</b>", styles["body"]),
                 _para("<b>Link Bug</b>", styles["body"]),
                 _para("<b>Catatan</b>", styles["body"])]]
    bug_count = 0
    for i, f in enumerate(findings_sorted, 1):
        urls = f.urls or ([f.target] if (f.target or "").startswith(("http://", "https://")) else [])
        if not urls:
            continue
        bug_count += 1
        link_html = "<br/>".join(
            f'<link href="{u}"><font color="#1F77B4">'
            f'{(u if len(u) <= 90 else u[:87] + "...")}</font></link>'
            for u in urls
        )
        bug_rows.append([_para(str(i), styles["body"]),
                         _severity_pill(f.severity, styles),
                         _para(f.module, styles["body"]),
                         _para(link_html, styles["body"]),
                         _para(f.title, styles["body"])])

    if bug_count == 0:
        story.append(_para(
            "Tidak ada link bug spesifik yang dapat diekstrak dari hasil scan. "
            "Lihat bab 4 untuk detail tiap temuan.",
            styles["muted"],
        ))
    else:
        bug_table = Table(
            bug_rows,
            colWidths=[1.0 * cm, 2.4 * cm, 2.6 * cm, 6.5 * cm, 4.0 * cm],
            repeatRows=1, hAlign="LEFT",
        )
        bug_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5D8DC")),
        ]))
        story.append(bug_table)

    # ============== LAMPIRAN A: MODULES YANG DIJALANKAN ===================
    story.append(PageBreak())
    story.append(_para("Lampiran A. Modul yang Dijalankan", styles["h1"]))
    mods = config.resolve_modules()
    cols = 3
    rows = [mods[i:i + cols] for i in range(0, len(mods), cols)]
    data = [[_para(m, styles["body"]) for m in row] + [""] * (cols - len(row)) for row in rows]
    if data:
        t = Table(data, colWidths=[5.5 * cm] * cols, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5D8DC")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5D8DC")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    story.append(Spacer(1, 0.4 * cm))
    story.append(_para(
        "Untuk daftar lengkap definisi setiap modul, lihat README repositori Cyberloka.",
        styles["muted"],
    ))

    # ============== LAMPIRAN B: GLOSSARY ==================================
    story.append(PageBreak())
    story.append(_para("Lampiran B. Glossary Istilah Keamanan", styles["h1"]))
    story.append(_para(
        "Daftar istilah dan singkatan yang digunakan di laporan ini.",
        styles["muted"],
    ))
    gl_rows = [[_para("<b>Istilah</b>", styles["body"]),
                _para("<b>Penjelasan</b>", styles["body"])]]
    for term, expl in GLOSSARY:
        gl_rows.append([_para(f"<b>{term}</b>", styles["body"]),
                        _para(expl, styles["body"])])
    gl_table = Table(gl_rows, colWidths=[3.5 * cm, 13 * cm], hAlign="LEFT", repeatRows=1)
    gl_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5D8DC")),
    ]))
    story.append(gl_table)

    doc.build(story)


# ----------------------------- public API --------------------------------


def write_pdf(
    path: str | None,
    target: Target,
    config: ScanConfig,
    findings: list[Finding],
    out_dir: str | None = None,
) -> str:
    """Write the PDF report. Returns the actual path written."""
    if not path:
        path = auto_pdf_path(target, out_dir=out_dir)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    _build(str(p), target, config, findings)
    return str(p)
