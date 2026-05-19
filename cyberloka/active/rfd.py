"""Reflected File Download probe."""
from __future__ import annotations

from urllib.parse import urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PAYLOAD = '"||calc||"'


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # Coba probe path: <base>/cyberloka.bat?q=<payload>
        u = urlparse(target.base_url)
        url = f"{u.scheme}://{u.netloc}/cyberloka.bat?q={PAYLOAD}"
        r = client.get(url)
        if r is None or r.status_code >= 400:
            return findings
        ctype = r.headers.get("Content-Type", "")
        cd = r.headers.get("Content-Disposition", "")
        body = r.text or ""
        # RFD klasik: response berisi payload yang dipantulkan + tidak set Content-Disposition
        # sehingga browser menyimpan dengan ekstensi dari URL.
        if PAYLOAD in body and "json" in ctype.lower() and "attachment" not in cd.lower():
            findings.append(Finding(
                module="rfd",
                title="Endpoint berpotensi Reflected File Download",
                severity=Severity.MEDIUM,
                description=("Server mengembalikan input pengguna pada response yang "
                             "tidak set `Content-Disposition`. Browser dapat tertipu "
                             "menyimpan response dengan ekstensi dari URL (`.bat`/`.cmd`)."),
                target=url, evidence=f"Content-Type={ctype}; CD={cd}",
                cwe="CWE-20", confidence="tentative",
                remediation=("Set `Content-Disposition: attachment; filename=\"safe.json\"` "
                             "untuk semua API yang mengembalikan input user, dan filter "
                             "karakter `\"`, `|` di output."),
            ))
    finally:
        client.close()
    return findings
