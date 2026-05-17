"""Directory listing exposure check."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

CANDIDATE_DIRS = ["/", "/uploads/", "/files/", "/static/", "/assets/", "/images/", "/img/", "/backup/", "/old/", "/tmp/"]
SIG = re.compile(r"<title>Index of /|Directory listing for ", re.I)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for d in CANDIDATE_DIRS:
            url = urljoin(target.origin + "/", d)
            resp = client.get(url, allow_redirects=False)
            if resp is None or resp.status_code != 200:
                continue
            if SIG.search(resp.text or ""):
                findings.append(
                    Finding(
                        module="dirlist",
                        title=f"Directory listing aktif: {url}",
                        severity=Severity.MEDIUM,
                        description=(
                            "Server menampilkan daftar isi direktori. Attacker dapat menelusuri "
                            "file untuk mencari konfigurasi/backup."
                        ),
                        target=url,
                        remediation=(
                            "Matikan autoindex / directory listing di web server "
                            "(`autoindex off` di Nginx, `Options -Indexes` di Apache)."
                        ),
                    )
                )
    finally:
        client.close()
    return findings
