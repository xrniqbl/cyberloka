"""Directory listing exposure — verification-first.

Bukan sekadar signature `<title>Index of /`. Kita konfirmasi STRUKTUR listing
sungguhan: signature autoindex + tautan parent-directory atau beberapa tautan file.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

CANDIDATE_DIRS = ["/", "/uploads/", "/files/", "/static/", "/assets/", "/images/", "/img/", "/backup/", "/old/", "/tmp/"]
SIG = re.compile(r"<title>\s*Index of /|Directory listing for ", re.I)
PARENT_RE = re.compile(r'href=["\']\.\./?["\']|>Parent Directory<', re.I)
LINK_RE = re.compile(r'<a\s+href=["\'][^"\']+["\']', re.I)


def _is_real_listing(body: str) -> bool:
    if not SIG.search(body):
        return False
    return bool(PARENT_RE.search(body)) or len(LINK_RE.findall(body)) >= 3


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for d in CANDIDATE_DIRS:
            url = urljoin(target.origin + "/", d)
            resp = client.get(url, allow_redirects=False)
            if resp is None or resp.status_code != 200:
                continue
            if _is_real_listing(resp.text or ""):
                findings.append(
                    Finding(
                        module="dirlist",
                        title=f"Directory listing TERVERIFIKASI aktif: {url}",
                        severity=Severity.MEDIUM,
                        confidence="confirmed",
                        description=(
                            "Server menampilkan daftar isi direktori (autoindex) lengkap dengan tautan "
                            "file/parent directory. Attacker dapat menelusuri file mencari konfigurasi/backup."
                        ),
                        target=url,
                        evidence="autoindex signature + struktur tautan file terdeteksi",
                        remediation=(
                            "Matikan autoindex / directory listing di web server "
                            "(`autoindex off` di Nginx, `Options -Indexes` di Apache)."
                        ),
                    )
                )
    finally:
        client.close()
    return findings
