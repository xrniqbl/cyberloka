"""SRI (Subresource Integrity) Missing — strict-validation v0.10.4.

Cek apakah <script src="https://cdn..."> dimuat tanpa attribute integrity.
Tanpa SRI, CDN yang disusupi bisa inject malicious code ke semua pengunjung.

Validasi:
  1. Parse HTML untuk tag <script> dan <link> yang memuat resource dari CDN.
  2. Cek apakah ada attribute integrity="sha...".
  3. Hanya laporkan untuk external CDN (bukan same-origin).
  4. Skip jika resource dari domain yang sama.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

# Script tags with external src
SCRIPT_TAG_RE = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
    re.IGNORECASE,
)

# Link tags (CSS) with external href
LINK_TAG_RE = re.compile(
    r"<link\b[^>]*\bhref\s*=\s*[\"']([^\"']+\.(?:css|js))[\"'][^>]*>",
    re.IGNORECASE,
)

# Integrity attribute check
INTEGRITY_RE = re.compile(r"\bintegrity\s*=\s*[\"']sha(?:256|384|512)-", re.IGNORECASE)

# Known CDN domains
CDN_DOMAINS = {
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "ajax.googleapis.com", "cdn.bootcdn.net", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "cdn.tailwindcss.com",
    "code.jquery.com", "fonts.googleapis.com",
    "cdn.datatables.net", "cdn.socket.io",
}


def _is_external_cdn(url: str, target_domain: str) -> bool:
    """Check if URL points to external CDN (not same origin)."""
    if not url.startswith("http"):
        return False
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host == target_domain:
        return False
    # Check if it's a known CDN or clearly external
    if any(cdn in host for cdn in CDN_DOMAINS):
        return True
    # Any external https resource qualifies
    return host != target_domain and "." in host


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Website memuat script dari CDN eksternal tanpa verifikasi integritas — "
        "jika CDN disusupi, semua pengunjung website Anda akan terkena malware."
    )
    awam_steps = [
        "Website Anda memuat JavaScript/CSS dari server pihak ketiga (CDN).",
        "Tidak ada attribute 'integrity' untuk memverifikasi isi file.",
        "Jika CDN diretas, penyerang bisa mengubah isi file JavaScript.",
        "Semua pengunjung website Anda akan menjalankan kode berbahaya.",
        "Penyerang bisa mencuri login, inject skimmer kartu kredit, dll.",
    ]
    try:
        resp = client.get(target.base_url)
        if resp is None or resp.status_code != 200:
            return findings

        body = resp.text or ""
        target_domain = urlparse(target.base_url).hostname or ""
        missing_sri: list[tuple[str, str]] = []  # (url, tag_type)

        # Check script tags
        for m in SCRIPT_TAG_RE.finditer(body):
            full_tag = body[m.start():m.end()]
            src = m.group(1)
            if _is_external_cdn(src, target_domain):
                if not INTEGRITY_RE.search(full_tag):
                    missing_sri.append((src, "script"))

        # Check link tags
        for m in LINK_TAG_RE.finditer(body):
            full_tag = body[m.start():m.end()]
            href = m.group(1)
            if _is_external_cdn(href, target_domain):
                if not INTEGRITY_RE.search(full_tag):
                    missing_sri.append((href, "link"))

        if not missing_sri:
            return findings

        # Limit to first 10
        missing_sri = missing_sri[:10]

        curl_cmd = (
            f"# Check SRI missing on external resources\n"
            f"curl -s '{target.base_url}' | "
            f"grep -oP '<script[^>]+src=\"https://[^\"]+\"[^>]*>' | "
            f"grep -v 'integrity='"
        )

        proof = ValidationProof(
            method="html-parse+integrity-attribute-check",
            confirmed=True,
            steps=[
                f"GET {target.base_url} → parse HTML.",
                f"Ditemukan {len(missing_sri)} external resource tanpa integrity attribute.",
                f"Resources: {[u for u, _ in missing_sri[:5]]}.",
                "Semua dari CDN eksternal (bukan same-origin).",
            ],
            samples=[f"{t}:{u}" for u, t in missing_sri[:5]],
        )

        findings.append(Finding(
            module="sri_missing",
            title=f"SRI missing pada {len(missing_sri)} resource CDN eksternal",
            severity=Severity.LOW,
            description=(
                f"Halaman utama memuat {len(missing_sri)} resource dari CDN eksternal "
                f"tanpa attribute integrity (SRI). Jika CDN compromised, "
                f"penyerang bisa inject kode berbahaya yang dijalankan di browser "
                f"semua pengunjung. Resources: {', '.join(u for u, _ in missing_sri[:3])}."
            ),
            target=target.base_url,
            urls=[u for u, _ in missing_sri[:5]],
            evidence=f"missing_sri_count={len(missing_sri)}, resources={[u for u, _ in missing_sri[:5]]}",
            cwe="CWE-353",
            confidence="confirmed",
            remediation=(
                "1. Tambahkan attribute integrity pada semua tag <script> dan <link> eksternal.\n"
                "2. Generate hash: `cat file.js | openssl dgst -sha384 -binary | openssl base64 -A`.\n"
                "3. Tambahkan crossorigin='anonymous' bersama integrity.\n"
                "4. Gunakan bundler yang auto-generate SRI (webpack-subresource-integrity).\n"
                "5. Pertimbangkan self-hosting critical JS daripada CDN."
            ),
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
            ],
            extra=build_extra(
                proof=proof,
                awam_steps=awam_steps,
                awam_summary=awam_summary,
                extra={"curl_cmd": curl_cmd, "missing_count": len(missing_sri)},
            ),
        ))
    finally:
        client.close()
    return findings
