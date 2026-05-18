"""Detect mixed content + missing Subresource Integrity (SRI) on cross-origin scripts."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if target.scheme != "https":
        return findings
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None:
            return findings
        soup = BeautifulSoup(resp.text or "", "html.parser")

        mixed: list[str] = []
        for tag in soup.find_all(["script", "link", "img", "iframe", "video", "audio", "source"]):
            src = tag.get("src") or tag.get("href")
            if not src:
                continue
            absolute = urljoin(target.base_url, src)
            if absolute.startswith("http://"):
                mixed.append(absolute)
        if mixed:
            findings.append(
                Finding(
                    module="mixed_content",
                    title="Mixed content: resource HTTP di halaman HTTPS",
                    severity=Severity.MEDIUM,
                    description=(
                        "Halaman HTTPS memuat resource lewat HTTP. Browser modern memblokir "
                        "atau mendowngrade keamanan halaman."
                    ),
                    target=target.base_url,
                    evidence="\n".join(mixed[:15]),
                    cwe="CWE-319",
                    remediation="Ubah semua URL resource ke HTTPS. Tambahkan CSP `upgrade-insecure-requests`.",
                )
            )

        host = urlparse(target.base_url).netloc
        missing_sri: list[str] = []
        for tag in soup.find_all("script"):
            src = tag.get("src")
            if not src:
                continue
            absolute = urljoin(target.base_url, src)
            ext_host = urlparse(absolute).netloc
            if ext_host and ext_host != host:
                if not tag.get("integrity"):
                    missing_sri.append(absolute)
        if missing_sri:
            findings.append(
                Finding(
                    module="mixed_content",
                    title="Cross-origin <script> tanpa Subresource Integrity",
                    severity=Severity.LOW,
                    description=(
                        "Script dari domain pihak ketiga tidak menyertakan atribut "
                        "`integrity`. Jika CDN dikompromikan, attacker dapat menyuntik kode."
                    ),
                    target=target.base_url,
                    evidence="\n".join(missing_sri[:15]),
                    cwe="CWE-353",
                    remediation=(
                        "Tambahkan atribut `integrity=\"sha384-...\"` dan `crossorigin=\"anonymous\"` "
                        "pada tag <script> dan <link rel=stylesheet> dari third-party CDN."
                    ),
                    references=[
                        "https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity"
                    ],
                )
            )
    finally:
        client.close()
    return findings
