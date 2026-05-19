"""Adminer.php exposed in webroot."""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = [
    "/adminer.php", "/adminer/", "/adminer/adminer.php",
    "/db/adminer.php", "/admin/adminer.php", "/_adminer.php",
    "/sql/adminer.php", "/database/adminer.php",
]
SIGNATURES = ("Adminer", "adminer.css", "adminer.js", "Login - Adminer")


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            body = (r.text or "")[:8192]
            if not any(s in body for s in SIGNATURES):
                continue
            findings.append(Finding(
                module="adminer_exposed",
                title=f"Adminer.php ter-expose di webroot: {path}",
                severity=Severity.HIGH,
                description=(
                    "File Adminer (DB management tool single-file) ditemukan "
                    "di webroot. Bila kredensial DB lemah / dipakai brute-force, "
                    "akses ke seluruh database adalah satu klik. Adminer juga "
                    "dapat dipakai sebagai SSRF ke DB internal mana saja."
                ),
                target=url,
                urls=[url],
                evidence=f"GET {url} -> 200; UI Adminer terdeteksi",
                cwe="CWE-538",
                confidence="confirmed",
                remediation=(
                    "Hapus adminer.php dari production. Bila perlu, batasi "
                    "akses dengan IP allowlist + basic-auth di reverse-proxy. "
                    "Jangan pernah men-deploy file admin DB ke production server."
                ),
                references=[
                    "https://www.adminer.org/en/",
                ],
            ))
            break
    finally:
        client.close()
    return findings
