"""XSLT injection probe — verification-first (marker aritmatika terkomputasi).

Masalah versi lama (false positive CRITICAL):
  Marker `CYBERLOKA-XSLT-OK` ada sebagai teks LITERAL di dalam stylesheet payload
  (`<xsl:template match="/">CYBERLOKA-XSLT-OK</xsl:template>`). Endpoint yang sekadar
  MEMANTULKAN body XML — echo, pesan error yang menyertakan input, atau simpan-lalu-
  tampil — memunculkan marker itu TANPA processor XSLT pernah berjalan. Hasilnya:
  temuan ditandai `confirmed` padahal hanya refleksi input (prediksi, bukan bukti).

Pendekatan baru — kebal refleksi (prinsip sama dengan modul `cmdi`):
  Stylesheet menghitung perkalian dua angka acak lewat `<xsl:value-of select="A*B"/>`
  yang dibungkus marker unik `CLK<hasil>END`. Hanya dilaporkan bila respons memuat
  HASIL perkalian (string yang TIDAK pernah ada di teks payload) DAN ekspresi/markup
  XSL mentah TIDAK terpantul. Server yang sekadar memantulkan input mengembalikan
  ekspresi mentah `<xsl:value-of select="A*B"/>`, bukan hasilnya, sehingga tidak
  mungkin memicu temuan. Match HANYA terjadi bila processor XSLT benar-benar
  mengevaluasi stylesheet → bukti pasti, bukan tebakan.
"""
from __future__ import annotations

import random

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state


def _build_probe(a: int, b: int) -> str:
    """Stylesheet yang HASILNYA (A*B) hanya muncul bila benar-benar dievaluasi."""
    return (
        '<?xml version="1.0"?>\n'
        '<xsl:stylesheet version="1.0" '
        'xmlns:xsl="http://www.w3.org/1999/XSL/Transform">\n'
        '<xsl:output method="text"/>\n'
        '<xsl:template match="/">'
        f'CLK<xsl:value-of select="{a}*{b}"/>END'
        '</xsl:template>\n'
        '</xsl:stylesheet>'
    )


def _is_executed(body: str, expected: str, literal_expr: str) -> bool:
    """True hanya bila stylesheet TEREKSEKUSI, bukan terpantul mentah.

    - `expected` (CLK<A*B>END) hadir: hasil perkalian, mustahil dari refleksi karena
      digit hasil tidak pernah ada di teks payload.
    - `literal_expr` (A*B) TIDAK ada: ekspresi mentah tidak ikut terpantul.
    - markup `<xsl:value-of` TIDAK ada: body bukan pantulan stylesheet.
    """
    return (
        expected in body
        and literal_expr not in body
        and "<xsl:value-of" not in body
    )


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    candidates = []
    if s:
        for u in s.urls:
            if any(k in u.lower() for k in ("xslt", "transform", "xml")):
                candidates.append(u)
    if not candidates:
        return findings
    client = HttpClient(config)
    try:
        for url in candidates[:3]:
            a, b = random.randint(10_000, 99_999), random.randint(10_000, 99_999)
            expected = f"CLK{a * b}END"
            literal_expr = f"{a}*{b}"
            r = client.post(
                url,
                data=_build_probe(a, b),
                headers={"Content-Type": "application/xslt+xml"},
            )
            if r is None:
                continue
            body = r.text or ""
            if _is_executed(body, expected, literal_expr):
                findings.append(Finding(
                    module="xslt_injection", target=url,
                    title="XSLT injection TERVERIFIKASI (stylesheet dievaluasi server)",
                    severity=Severity.CRITICAL,
                    confidence="confirmed",
                    description=(
                        "Processor XSLT server mengevaluasi stylesheet yang dikirim klien: "
                        "respons memuat HASIL perkalian aritmatika yang disuntikkan, bukan "
                        "teks payload yang dipantulkan. Attacker dapat mengontrol transformasi "
                        "— sering berujung pembacaan file lokal, SSRF, atau RCE tergantung engine."
                    ),
                    evidence=(
                        f"XSLT mengevaluasi {literal_expr} -> {expected} "
                        "(ekspresi & markup mentah tidak terpantul → bukan refleksi)"
                    ),
                    cwe="CWE-91",
                    remediation=(
                        "Jangan terima XSL stylesheet dari user. Pakai stylesheet hardcoded, "
                        "dan nonaktifkan fitur ekstensi/eksternal pada processor XSLT."
                    ),
                ))
                return findings
    finally:
        client.close()
    return findings
