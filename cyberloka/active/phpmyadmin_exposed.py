"""phpMyAdmin exposed in webroot."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    catch_all_control,
    is_catch_all_response,
    is_soft_200,
)
from cyberloka.core.config import ScanConfig

PATHS = [
    "/phpmyadmin/", "/pma/", "/myadmin/", "/dbadmin/", "/PHPMyAdmin/",
    "/phpMyAdmin/", "/mysql/", "/sql/", "/db/", "/manager/",
]
# Signature KUAT khas halaman phpMyAdmin asli (bukan sekadar substring
# "phpmyadmin" generik yang bisa muncul di halaman/JS situs lain).
STRONG_SIGNATURES = (
    "pma_password", "pma_username", "PMA_VERSION", "pmahomme",
    "set_session", "<title>phpMyAdmin", "phpmyadmin.css", "js/vendor",
)
TITLE_RE = re.compile(r"<title>[^<]*phpMyAdmin", re.I)
# Lokasi redirect yang menandakan instalasi phpMyAdmin nyata.
LOCATION_HINTS = ("phpmyadmin", "/pma/", "index.php?route", "pma_")


def _is_real_pma(body: str, location: str) -> bool:
    if TITLE_RE.search(body):
        return True
    if any(s in body for s in STRONG_SIGNATURES):
        return True
    loc = location.lower()
    return any(h in loc for h in LOCATION_HINTS)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    control_body = catch_all_control(client, target.origin + "/")
    try:
        for path in PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code not in (200, 301, 302):
                continue
            body = (r.text or "")[:8192]
            location = r.headers.get("Location") or ""
            # Tolak soft-404 / SPA shell / catch-all (akar false-positive).
            if r.status_code == 200 and (
                is_soft_200(r) or is_catch_all_response(r.text or "", control_body)
            ):
                continue
            # Wajib signature KUAT phpMyAdmin, bukan substring generik.
            if not _is_real_pma(body, location):
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
                evidence=f"GET {url} -> {r.status_code}; signature phpMyAdmin kuat terdeteksi",
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
