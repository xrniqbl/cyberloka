"""PDP Data Retention / X-Robots-Tag Check — strict-validation v0.10.4.

Cek apakah halaman yang memuat PII (profil, dashboard, akun) memiliki
header X-Robots-Tag: noarchive untuk mencegah caching oleh search engines.

Validasi:
  1. Identifikasi halaman yang kemungkinan memuat PII (profil, account, dashboard).
  2. Cek response headers untuk X-Robots-Tag: noarchive/noindex.
  3. Cek <meta name="robots"> di HTML.
  4. Jika tidak ada → data PII bisa ter-cache di Google Cache / Wayback Machine.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

PII_PAGES = [
    "/profile", "/account", "/dashboard",
    "/my-account", "/user/profile", "/settings",
    "/api/me", "/account/settings",
    "/member/profile", "/akun", "/profil",
    "/data-diri", "/personal-info",
]

# Indicators that page contains PII
PII_INDICATORS = re.compile(
    r"(email|phone|telepon|alamat|address|nama.lengkap|full.name|"
    r"tanggal.lahir|birth.date|nik|no.ktp|nomor.hp)",
    re.IGNORECASE,
)


def _has_noarchive(resp) -> bool:
    """Check for noarchive/noindex in headers and meta tags."""
    if resp is None:
        return True  # Can't check, assume OK

    # Check X-Robots-Tag header
    robots_header = (resp.headers.get("X-Robots-Tag", "") or "").lower()
    if "noarchive" in robots_header or "noindex" in robots_header:
        return True

    # Check Cache-Control: private
    cc = (resp.headers.get("Cache-Control", "") or "").lower()
    if "private" in cc and "no-store" in cc:
        return True

    # Check <meta name="robots">
    body = (resp.text or "")[:5000].lower()
    meta_robots = re.search(
        r'<meta\s+name=["\']robots["\'][^>]*content=["\']([^"\']+)["\']',
        body,
    )
    if meta_robots:
        content = meta_robots.group(1).lower()
        if "noarchive" in content or "noindex" in content:
            return True

    return False


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Halaman yang memuat data pribadi tidak dilindungi dari caching oleh "
        "search engine — data bisa muncul di Google Cache atau Wayback Machine."
    )
    awam_steps = [
        "Search engine (Google, Bing) mengindex halaman profil/akun pelanggan.",
        "Google menyimpan salinan halaman di 'Google Cache'.",
        "Wayback Machine menyimpan arsip halaman secara permanen.",
        "Siapa pun bisa membuka cache/arsip dan melihat data pribadi pelanggan.",
        "Data tetap tersedia meskipun sudah dihapus dari website asli.",
    ]
    try:
        pages_without_noarchive: list[tuple[str, list[str]]] = []

        for path in PII_PAGES:
            url = urljoin(target.base_url, path)
            resp = client.get(url)
            if resp is None or resp.status_code != 200:
                continue

            body = resp.text or ""
            # Check if page actually contains PII-like content
            pii_hits = PII_INDICATORS.findall(body[:5000])
            if len(pii_hits) < 2:
                continue

            # Check for noarchive protection
            if _has_noarchive(resp):
                continue

            pages_without_noarchive.append((url, pii_hits[:5]))

        if not pages_without_noarchive:
            return findings

        curl_cmd = (
            f"# Check X-Robots-Tag on PII pages\n"
            + "\n".join(
                f"curl -s -I '{url}' | grep -i 'x-robots-tag\\|cache-control'"
                for url, _ in pages_without_noarchive[:3]
            )
        )

        proof = ValidationProof(
            method="pii-page-detection+robots-header-check",
            confirmed=True,
            steps=[
                f"Checked {len(PII_PAGES)} potential PII pages.",
                f"{len(pages_without_noarchive)} pages with PII indicators lack noarchive.",
                f"Pages: {[u for u, _ in pages_without_noarchive[:5]]}.",
                "No X-Robots-Tag: noarchive, no meta robots noarchive.",
                "No Cache-Control: private, no-store.",
            ],
            samples=[f"{u}: pii={h}" for u, h in pages_without_noarchive[:3]],
        )

        findings.append(Finding(
            module="pdp_data_retention",
            title=f"{len(pages_without_noarchive)} halaman PII tanpa proteksi noarchive",
            severity=Severity.LOW,
            description=(
                f"Ditemukan {len(pages_without_noarchive)} halaman yang mengandung "
                f"indikator data pribadi (PII) tetapi tidak memiliki header "
                f"X-Robots-Tag: noarchive atau meta robots noarchive. Halaman ini "
                f"berpotensi dicache oleh search engine atau web archive, "
                f"menyebabkan data pribadi tersimpan permanen di pihak ketiga."
            ),
            target=target.base_url,
            urls=[u for u, _ in pages_without_noarchive[:5]],
            evidence=f"pages_without_noarchive={len(pages_without_noarchive)}",
            cwe="CWE-525",
            confidence="confirmed",
            remediation=(
                "1. Tambahkan header X-Robots-Tag: noindex, noarchive pada halaman PII.\n"
                "2. Atau tambahkan <meta name='robots' content='noindex, noarchive'>.\n"
                "3. Set Cache-Control: private, no-store pada halaman yang memuat PII.\n"
                "4. Submit URL removal request ke Google Search Console untuk halaman yang sudah terindex.\n"
                "5. Comply UU PDP — data pribadi tidak boleh disimpan lebih lama dari tujuan."
            ),
            references=[
                "https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag",
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
