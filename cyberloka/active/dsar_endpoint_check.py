"""DSAR Endpoint Check — strict-validation v0.10.4.

Cek apakah endpoint Data Subject Access Request (DSAR) tersedia.
UU PDP mewajibkan controller menyediakan mekanisme bagi subjek data untuk
mengakses/mengunduh data pribadinya.

Validasi:
  1. Probe endpoint DSAR yang umum (/api/account/export, /account/data-download, dll.).
  2. Cek apakah endpoint merespons (bukan 404).
  3. Jika SEMUA endpoint 404 → tidak ada mekanisme DSAR → finding.
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
    is_soft_200,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

DSAR_PATHS = [
    "/api/account/export", "/api/v1/account/export",
    "/account/data-download", "/account/export",
    "/api/user/data-export", "/api/me/export",
    "/api/gdpr/export", "/api/privacy/export",
    "/api/data-request", "/api/v1/data-request",
    "/privacy/data-download", "/settings/data-export",
    "/account/download-data", "/api/account/download",
    "/my-data", "/data-portability",
    "/api/dsar", "/api/v1/dsar",
    "/api/hak-akses", "/api/unduh-data",
]

# Pages that might link to DSAR functionality
DSAR_LINK_PATTERNS = [
    "data-download", "data-export", "export-data",
    "download-my-data", "request-data", "data portability",
    "unduh data", "hak akses data", "minta data",
    "download your data", "request your data",
    "dsar", "data subject",
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Tidak ditemukan mekanisme bagi pengguna untuk mengunduh data pribadinya — "
        "kemungkinan melanggar hak akses subjek data (UU PDP Pasal 8)."
    )
    awam_steps = [
        "Pengguna ingin mengunduh seluruh data pribadi yang disimpan aplikasi.",
        "Pengguna mencari fitur 'Download My Data' atau 'Export Data' — tidak ada.",
        "Tanpa fitur ini, pengguna tidak bisa menggunakan hak aksesnya (UU PDP).",
        "Regulator bisa memberikan sanksi karena tidak menyediakan mekanisme DSAR.",
        "Pengguna bisa mengajukan gugatan class action.",
    ]
    try:
        # Step 1: Check if any DSAR endpoint exists
        found_endpoints: list[str] = []
        for path in DSAR_PATHS:
            url = urljoin(target.base_url, path)
            resp = client.get(url)
            if resp is None:
                continue
            # Accept anything that's not a clear 404
            if resp.status_code in (200, 201, 202, 301, 302, 401, 403):
                if not is_soft_200(resp):
                    found_endpoints.append(url)

        # Step 2: Check main page / settings for DSAR links
        has_dsar_link = False
        for check_path in ["/settings", "/account", "/privacy", "/profil"]:
            url = urljoin(target.base_url, check_path)
            resp = client.get(url)
            if resp and resp.status_code == 200:
                body = (resp.text or "").lower()
                if any(pat in body for pat in DSAR_LINK_PATTERNS):
                    has_dsar_link = True
                    break

        # If DSAR endpoint exists or link found → no issue
        if found_endpoints or has_dsar_link:
            return findings

        # No DSAR mechanism found → finding
        curl_cmd = (
            f"# Check DSAR endpoints availability\n"
            + "\n".join(
                f"curl -s -o /dev/null -w '%{{http_code}} {path}\\n' '{urljoin(target.base_url, path)}'"
                for path in DSAR_PATHS[:5]
            )
        )

        proof = ValidationProof(
            method="dsar-endpoint-probe+link-search",
            confirmed=True,
            steps=[
                f"Probed {len(DSAR_PATHS)} endpoint DSAR umum — semua 404/tidak ada.",
                "Checked /settings, /account, /privacy untuk link DSAR — tidak ditemukan.",
                "Tidak ada mekanisme data export/download yang terdeteksi.",
                "Kesimpulan: kemungkinan tidak comply UU PDP Pasal 8 (hak akses).",
            ],
            samples=[f"checked_paths={DSAR_PATHS[:5]}", "all_returned=404/soft-200"],
        )

        findings.append(Finding(
            module="dsar_endpoint_check",
            title="Tidak ditemukan mekanisme DSAR (Data Subject Access Request)",
            severity=Severity.LOW,
            description=(
                f"Setelah memeriksa {len(DSAR_PATHS)} endpoint DSAR yang umum "
                f"dan halaman settings/privacy, tidak ditemukan mekanisme bagi "
                f"pengguna untuk mengunduh/mengekspor data pribadinya. UU PDP "
                f"No. 27/2022 Pasal 8 mewajibkan pengendali data menyediakan "
                f"akses bagi subjek data untuk memperoleh salinan datanya."
            ),
            target=target.base_url,
            urls=[target.base_url],
            evidence=f"dsar_endpoints_found=0, dsar_links_found=false",
            cwe="CWE-693",
            confidence="firm",
            remediation=(
                "1. Implementasi endpoint data export (JSON/ZIP) di /account/data-download.\n"
                "2. Sediakan UI button 'Download My Data' di halaman settings.\n"
                "3. Proses harus selesai dalam 3x24 jam (sesuai UU PDP).\n"
                "4. Format data harus machine-readable (JSON/CSV).\n"
                "5. Dokumentasi prosedur DSAR di Privacy Policy.\n"
                "6. Log setiap request DSAR untuk audit trail."
            ),
            references=[
                "https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022",
            ],
            extra=build_extra(
                proof=proof,
                awam_steps=awam_steps,
                awam_summary=awam_summary,
                extra={"curl_cmd": curl_cmd},
            ),
        ))
    finally:
        client.close()
    return findings
