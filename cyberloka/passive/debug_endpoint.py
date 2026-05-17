"""Debug & development endpoint detector.

Cek path yang biasanya hanya ada di environment dev tapi tidak sengaja
ter-deploy ke production.
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# (path, marker_substring_to_confirm, severity)
DEBUG_PATHS = [
    # Symfony
    ("/_profiler", "WebProfiler", Severity.HIGH),
    ("/_profiler/", "WebProfiler", Severity.HIGH),
    ("/_wdt", "Web Debug Toolbar", Severity.HIGH),
    # Spring Boot Actuator
    ("/actuator/env", "activeProfiles", Severity.CRITICAL),
    ("/actuator/heapdump", "heapdump", Severity.CRITICAL),
    ("/actuator/threaddump", "threadName", Severity.HIGH),
    ("/actuator/beans", "beans", Severity.MEDIUM),
    ("/actuator/mappings", "mappings", Severity.MEDIUM),
    ("/actuator/configprops", "configurationProperties", Severity.HIGH),
    # Django
    ("/__debug__/", "Django Debug Toolbar", Severity.HIGH),
    ("/django-admin/", "Django administration", Severity.MEDIUM),
    # Laravel
    ("/_ignition/health-check", "ignition", Severity.HIGH),
    ("/telescope", "Telescope", Severity.HIGH),
    ("/horizon", "Horizon", Severity.MEDIUM),
    ("/debugbar/", "PhpDebugBar", Severity.HIGH),
    # PHP
    ("/phpinfo.php", "phpinfo()", Severity.CRITICAL),
    ("/info.php", "PHP Version", Severity.HIGH),
    ("/test.php", "PHP Version", Severity.MEDIUM),
    # Generic debug
    ("/debug", "debug", Severity.LOW),
    ("/trace", "trace", Severity.LOW),
    ("/_status", "status", Severity.LOW),
    ("/_health", "health", Severity.INFO),  # health biasanya ok publik
    # Node.js
    ("/_next/data/", "_next", Severity.LOW),  # Next.js — beberapa data exposed
    # Database admins
    ("/phpmyadmin/", "phpMyAdmin", Severity.HIGH),
    ("/adminer.php", "Adminer", Severity.HIGH),
    ("/pma/", "phpMyAdmin", Severity.HIGH),
    # Search/queue admin
    ("/_cluster/health", "cluster_name", Severity.HIGH),  # Elasticsearch
    ("/elasticsearch/", "elasticsearch", Severity.HIGH),
    ("/solr/admin/", "Solr Admin", Severity.HIGH),
    # Misc dev tools
    ("/swagger-ui/", "swagger-ui", Severity.LOW),
    ("/graphiql", "GraphiQL", Severity.LOW),
    ("/altair", "Altair GraphQL", Severity.LOW),
    # Status pages
    ("/server-status", "Server Status", Severity.HIGH),
    ("/server-info", "Server Information", Severity.HIGH),
    ("/nginx_status", "Active connections", Severity.HIGH),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path, marker, sev in DEBUG_PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            resp = client.get(url, allow_redirects=False)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if marker.lower() not in body.lower():
                # status 200 tapi tidak match marker — skip untuk hindari FP
                continue
            findings.append(
                Finding(
                    module="debug_endpoint",
                    title=f"Debug/dev endpoint ter-ekspos: {path}",
                    severity=sev,
                    description=(
                        "Endpoint debug/development terdeteksi di production. "
                        "Tergantung jenisnya, dapat memuat: env variables (DB password, "
                        "API keys), heap dump (in-memory secrets), thread dump (kode "
                        "internal), atau memberi akses langsung ke DB/queue admin."
                    ),
                    target=url,
                    evidence=f"marker={marker!r} | size={len(body)} | snippet={truncate(body, 180)}",
                    cwe="CWE-489",
                    remediation=(
                        f"Disable {path} di production. Untuk Spring Boot: "
                        "`management.endpoints.web.exposure.include=health` saja. "
                        "Symfony: `APP_ENV=prod APP_DEBUG=0`. Django: `DEBUG=False`. "
                        "Laravel: hapus telescope/debugbar di production deps. "
                        "phpMyAdmin: pasang HTTP basic auth + IP whitelist + 2FA."
                    ),
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/",
                    ],
                )
            )
    finally:
        client.close()
    return findings
