"""Open Graph / link-preview SSRF probe.

Sosmed sering punya fitur: paste URL di post, server fetch metadata Open
Graph. Kalau fetcher tidak filter URL internal, bisa jadi SSRF.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

PREVIEW_HINTS = re.compile(
    r"(preview|unfurl|opengraph|og[-_]preview|link[-_]preview|fetch[-_]url)",
    re.I,
)
COMMON_PATHS = [
    "/api/preview", "/api/unfurl", "/api/og", "/api/link-preview",
    "/api/fetch-url", "/api/embed", "/api/oembed", "/api/og-preview",
    "/preview", "/unfurl",
]
PROBES = [
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata", "ami-id"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata", "instance/"),
    ("http://127.0.0.1/", "loopback", ""),
    ("http://localhost:80/", "localhost", ""),
    ("file:///etc/passwd", "file scheme", "root:"),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    candidates = set()
    s = get_state(config)
    if s:
        for u in s.urls + s.param_urls:
            if PREVIEW_HINTS.search(u):
                candidates.add(u)
    for p in COMMON_PATHS:
        candidates.add(urljoin(target.origin + "/", p.lstrip("/")))

    if not candidates:
        return findings

    client = HttpClient(config)
    try:
        for url in list(candidates)[:8]:
            # Skip kalau endpoint balas 404 untuk request normal
            r0 = client.get(url)
            if r0 is None or r0.status_code in (404, 405):
                continue

            for probe_url, label, marker in PROBES[:3]:
                # Coba kirim sebagai POST (paling umum) dan GET
                for method in ("POST", "GET"):
                    if method == "POST":
                        r = client.post(url, json={"url": probe_url, "link": probe_url})
                    else:
                        r = client.get(url, params={"url": probe_url, "link": probe_url})
                    if r is None or r.status_code >= 500:
                        continue
                    body = (r.text or "").lower()
                    # Marker spesifik = berhasil mencapai metadata
                    if marker and marker.lower() in body:
                        findings.append(Finding(
                            module="url_preview_ssrf",
                            target=url,
                            title=f"Link-preview fetcher rentan SSRF ke {label}",
                            severity=Severity.CRITICAL,
                            description=(
                                "Endpoint link-preview/Open-Graph mem-fetch URL "
                                "yang dikirim user TANPA memvalidasi destinasi.\n\n"
                                "SKENARIO SERANGAN:\n"
                                "1. Attacker post link `http://169.254.169.254/...` "
                                "ke timeline / DM / comment.\n"
                                "2. Server sosmed otomatis fetch URL untuk "
                                "menampilkan thumbnail/title.\n"
                                "3. Server menerima respons dari endpoint "
                                "metadata cloud (AWS IAM credentials, GCP "
                                "service account token).\n"
                                "4. Konten metadata muncul di preview kartu — "
                                "attacker dapat baca via screenshot atau "
                                "lewat respons API.\n"
                                "5. IAM token dipakai untuk akses S3/RDS — "
                                "seluruh database & file user terbongkar."
                            ),
                            evidence=(
                                f"Endpoint preview : {url}\n"
                                f"Probe URL        : {probe_url}\n"
                                f"Marker '{marker}' ditemukan di response\n"
                                f"Method           : {method}\n"
                                f"Verifikasi manual: kirim POST {url} dengan "
                                f"body `{{\"url\":\"{probe_url}\"}}` → response "
                                "akan memuat data internal."
                            ),
                            cwe="CWE-918",
                            confidence="confirmed",
                            remediation=(
                                "LANGKAH PERBAIKAN:\n"
                                "1. Saat menerima URL dari user, RESOLVE DNS dulu.\n"
                                "2. Tolak IP yang di range:\n"
                                "   - 127.0.0.0/8 (loopback)\n"
                                "   - 169.254.0.0/16 (link-local + cloud metadata)\n"
                                "   - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (private)\n"
                                "   - ::1, fc00::/7 (IPv6 loopback + private)\n"
                                "3. Tolak skema selain `http`/`https` (no `file:`, "
                                "`gopher:`, `dict:`).\n"
                                "4. Untuk AWS, migrasi ke IMDSv2 (`hop-limit=1`) "
                                "agar metadata tidak bisa di-fetch dari container.\n"
                                "5. Pakai library spesialis: `python-requests` "
                                "dengan custom adapter, atau Go `net.Dial` dengan "
                                "validasi IP setelah resolve.\n"
                                "6. Set timeout ketat (5 detik) + body limit (1MB) "
                                "untuk mencegah amplifikasi.\n\n"
                                "VERIFIKASI:\n"
                                "Setelah patch, kirim ulang URL test di atas. "
                                "Server harus return error 'Invalid URL' atau "
                                "'URL not allowed' — bukan content dari metadata."
                            ),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                                "https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/",
                            ],
                        ))
                        return findings
    finally:
        client.close()
    return findings
