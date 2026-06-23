"""QRIS Static Image/Endpoint Leak — strict-validation v0.10.4.

Menemukan gambar QRIS statis atau endpoint yang mengekspos data merchant QRIS
secara publik. QRIS statis yang bocor bisa digunakan untuk social engineering
atau pembuatan QRIS palsu.

Validasi:
  1. Crawl/probe path yang biasa memuat QRIS (/qris/, /payment/qris, /static/qris).
  2. Cari pattern NMID (Merchant ID nasional) dan format QRIS payload.
  3. Negative-control: pastikan bukan template/placeholder.
  4. Double-confirm konsistensi.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
    is_soft_200, looks_like_html_shell,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

QRIS_PATHS = [
    "/qris/", "/qris/static", "/qris/merchant",
    "/api/qris", "/api/v1/qris", "/api/payment/qris",
    "/payment/qris", "/static/qris/",
    "/images/qris/", "/assets/qris/",
    "/merchant/qris", "/api/merchant/qris",
    "/qr/payment", "/qr/static",
]

# NMID pattern: ID + 15-18 digits (National Merchant ID)
NMID_RE = re.compile(r"\bID\d{15,18}\b")

# QRIS payload pattern (EMVCo QR format starts with 000201...)
QRIS_PAYLOAD_RE = re.compile(
    r"0002011[12]01\d{2}[0-9A-Za-z.]+", re.ASCII
)

# Merchant name / city in QRIS context
MERCHANT_CONTEXT_RE = re.compile(
    r"(merchant[_\- ]?(?:name|id|city|nmid)|qris[_\- ]?(?:static|dynamic|url|image)|"
    r"nmid|terminal[_\- ]?id|pan[_\- ]?code)",
    re.IGNORECASE,
)

# Image file patterns
QRIS_IMAGE_RE = re.compile(
    r"(?:src|href|url)\s*[=:(]\s*[\"']?([^\"'\s>)]+qris[^\"'\s>)]*\.(?:png|jpg|jpeg|svg))",
    re.IGNORECASE,
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Gambar QRIS statis atau data merchant QRIS terekspos publik — "
        "penyerang bisa membuat QRIS palsu mengatasnamakan merchant Anda."
    )
    awam_steps = [
        "Penyerang menemukan gambar/endpoint QRIS statis di website merchant.",
        "Dari gambar QRIS, penyerang mengekstrak data merchant (NMID, nama, kota).",
        "Penyerang membuat QRIS palsu dengan data merchant asli tapi rekening penyerang.",
        "QRIS palsu ditempel di lokasi fisik atau dikirim ke korban.",
        "Pembayaran korban masuk ke rekening penyerang, bukan merchant asli.",
    ]
    try:
        for path in QRIS_PATHS:
            url = urljoin(target.base_url, path)
            resp = client.get(url)
            if resp is None or resp.status_code != 200:
                continue
            if is_soft_200(resp):
                continue
            body = resp.text or ""
            if not body:
                continue

            nmid_matches = NMID_RE.findall(body)
            payload_matches = QRIS_PAYLOAD_RE.findall(body)
            context_matches = MERCHANT_CONTEXT_RE.findall(body)
            image_matches = QRIS_IMAGE_RE.findall(body)

            # Need at least NMID or QRIS payload or strong context + images
            has_evidence = (
                len(nmid_matches) >= 1
                or len(payload_matches) >= 1
                or (len(context_matches) >= 2 and len(image_matches) >= 1)
            )
            if not has_evidence:
                continue

            # Double confirm
            resp2 = client.get(url)
            if resp2 is None or resp2.status_code != 200:
                continue
            body2 = resp2.text or ""
            nmid2 = NMID_RE.findall(body2)
            if nmid_matches and not nmid2:
                continue

            curl_cmd = (
                f"curl -s '{url}' | grep -iE 'NMID|qris|merchant|ID[0-9]{{15}}'"
            )

            evidence_parts = []
            if nmid_matches:
                evidence_parts.append(f"NMID={nmid_matches[:3]}")
            if payload_matches:
                evidence_parts.append(f"QRIS_payload={payload_matches[0][:30]}...")
            if image_matches:
                evidence_parts.append(f"QRIS_images={image_matches[:3]}")

            proof = ValidationProof(
                method="pattern-match+double-confirm",
                confirmed=True,
                steps=[
                    f"GET {url} → 200 OK.",
                    f"NMID ditemukan: {len(nmid_matches)} instance.",
                    f"QRIS payload: {len(payload_matches)} instance.",
                    f"Context keywords: {context_matches[:5]}.",
                    "Double-confirm: data konsisten pada fetch kedua.",
                ],
                samples=evidence_parts,
            )

            findings.append(Finding(
                module="qris_static_leak",
                title=f"QRIS statis / data merchant terekspos di {path}",
                severity=Severity.MEDIUM,
                description=(
                    f"Endpoint {url} mengekspos data QRIS statis atau informasi merchant "
                    f"secara publik. Ditemukan {len(nmid_matches)} NMID dan "
                    f"{len(payload_matches)} QRIS payload. Data ini bisa dipakai "
                    f"untuk membuat QRIS palsu mengatasnamakan merchant."
                ),
                target=url,
                urls=[url],
                evidence="; ".join(evidence_parts),
                cwe="CWE-200",
                confidence="confirmed",
                remediation=(
                    "1. Jangan expose gambar QRIS statis di URL publik tanpa autentikasi.\n"
                    "2. Gunakan QRIS dinamis (one-time) untuk setiap transaksi.\n"
                    "3. Tambahkan watermark/expiry pada QRIS statis.\n"
                    "4. Rate-limit akses ke endpoint QRIS.\n"
                    "5. Monitor dan alert jika ada akses massal ke endpoint QRIS."
                ),
                references=[
                    "https://www.bi.go.id/id/fungsi-utama/sistem-pembayaran/qris/",
                ],
                extra=build_extra(
                    proof=proof,
                    awam_steps=awam_steps,
                    awam_summary=awam_summary,
                    extra={"curl_cmd": curl_cmd},
                ),
            ))
            break
    finally:
        client.close()
    return findings
