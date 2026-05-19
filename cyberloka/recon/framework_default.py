"""Probe known framework default paths / debug pages."""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# (path, label, severity, marker substring required in body)
PATHS = [
    ("/actuator/env", "Spring actuator env", Severity.HIGH, "activeProfiles"),
    ("/actuator/health", "Spring actuator", Severity.LOW, "status"),
    ("/actuator/heapdump", "Spring actuator heapdump", Severity.CRITICAL, ""),
    ("/_ignition/execute-solution", "Laravel Ignition (CVE-2021-3129)", Severity.CRITICAL, ""),
    ("/console", "Werkzeug debug console", Severity.CRITICAL, "Werkzeug"),
    ("/server-status", "Apache server-status", Severity.HIGH, "Apache Server Status"),
    ("/server-info", "Apache server-info", Severity.MEDIUM, "Apache Server Information"),
    ("/wp-admin/", "WordPress admin", Severity.LOW, "wp-login"),
    ("/wp-login.php", "WordPress login", Severity.LOW, "wp-submit"),
    ("/admin/", "Generic admin path", Severity.LOW, ""),
    ("/manager/html", "Tomcat Manager", Severity.HIGH, "Tomcat"),
    ("/jolokia/", "Jolokia JMX bridge", Severity.HIGH, "jolokia"),
    ("/.env", "Env file", Severity.CRITICAL, "="),  # double-coverage with source_leak
    ("/phpmyadmin/", "phpMyAdmin", Severity.MEDIUM, "phpMyAdmin"),
    ("/swagger-ui.html", "Swagger UI v2", Severity.MEDIUM, "swagger"),
    ("/swagger-ui/", "Swagger UI v3", Severity.MEDIUM, "swagger"),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    base = target.origin + "/"
    try:
        for path, label, sev, marker in PATHS:
            url = urljoin(base, path.lstrip("/"))
            r = client.get(url)
            if r is None or r.status_code >= 400:
                continue
            body = r.text or ""
            if marker and marker.lower() not in body.lower():
                continue
            findings.append(Finding(
                module="framework_default",
                title=f"Endpoint default/admin terbuka: {label} ({path})",
                severity=sev,
                description=("Path framework/admin standar dapat diakses publik. Verifikasi "
                             "apakah perlu autentikasi atau seharusnya dimatikan di produksi."),
                target=url,
                evidence=f"HTTP {r.status_code}, marker='{marker}'",
                cwe="CWE-489",
                remediation=("Matikan endpoint debug/management di produksi, atau "
                             "lindungi dengan basic auth + IP allowlist."),
            ))
    finally:
        client.close()
    return findings
