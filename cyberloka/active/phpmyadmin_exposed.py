"""phpMyAdmin exposed in webroot."""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = [
    "/phpmyadmin/", "/pma/", "/myadmin/", "/dbadmin/", "/PHPMyAdmin/",
    "/phpMyAdmin/", "/mysql/", "/sql/", "/db/", "/manager/",
]
SIGNATURES = ("phpMyAdmin", "pma_password", "PMA_VERSION", "phpmyadmin")


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code not in (200, 301, 302):
                continue
            body = (r.text or "")[:8192]
            location = r.headers.get("Location") or ""
            if not (any(s in body for s in SIGNATURES)
                    or any(s.lower() in location.lower() for s in SIGNATURES)):
                continue
            findings.append(Finding(
                module="phpmyadmin_exposed",
                title=f"phpMyAdmin ter-expose: {path}",
                severity=Severity.HIGH,
                description=(
                    "Panel phpMyAdmin terbuka publik. Kombinasi dengan "
                    "kredensial DB lemah / CVE phpMyAdmin (mis. CVE-2018-12613 "
                    "LFI yang naik ke RCE via INTO OUTFILE) = takeover server."
                ),
                target=url,
                urls=[url],
                evidence=f"GET {url} -> {r.status_code}; signature phpMyAdmin terdeteksi",
                cwe="CWE-538",
                confidence="confirmed",
                remediation=(
                    "Jangan deploy phpMyAdmin di production. Bila perlu admin "
                    "DB jarak jauh, pakai SSH tunnel + bind ke localhost. "
                    "Bila tetap deploy, pasang IP allowlist ketat + basic-auth + "
                    "rate-limit + selalu update ke versi terbaru."
                ),
                references=[
                    "https://www.phpmyadmin.net/security/",
                ],
            ))
            break
    finally:
        client.close()
    return findings
