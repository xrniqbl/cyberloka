"""Probe known framework default / debug / admin paths — verification-first.

Modul lama menyatakan "terbuka" hanya dari HTTP 200 + marker lemah (mis. `/.env`
dengan marker `=`). Situs SPA mengembalikan index.html 200 untuk path apa pun →
false positive. Kini setiap path divalidasi: harus BUKAN catch-all/soft-404 (lihat
`core.probe`) DAN lolos validator konten spesifik (struktur .env, marker khas, dll).
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core import probe


def _marker(m: str):
    return lambda ctype, body: probe.body_has(body, m)


def _admin_like(ctype, body):
    low = body.lower()
    return any(t in low for t in ("login", "password", "<form", "sign in", "username"))


def _ignition(ctype, body):
    return probe.is_json_doc(ctype, body) or "ignition" in body.lower() or "illuminate\\" in body.lower()


# (path, label, severity, validator(ctype, body) -> bool)
PATHS = [
    ("/actuator/env", "Spring actuator env", Severity.HIGH, _marker("activeProfiles")),
    ("/actuator/health", "Spring actuator", Severity.LOW, _marker("status")),
    ("/actuator/heapdump", "Spring actuator heapdump", Severity.CRITICAL,
     lambda c, b: probe.is_binaryish(c)),
    ("/_ignition/execute-solution", "Laravel Ignition (CVE-2021-3129)", Severity.CRITICAL, _ignition),
    ("/console", "Werkzeug debug console", Severity.CRITICAL, _marker("Werkzeug")),
    ("/server-status", "Apache server-status", Severity.HIGH, _marker("Apache Server Status")),
    ("/server-info", "Apache server-info", Severity.MEDIUM, _marker("Apache Server Information")),
    ("/wp-admin/", "WordPress admin", Severity.LOW, _marker("wp-login")),
    ("/wp-login.php", "WordPress login", Severity.LOW, _marker("wp-submit")),
    ("/admin/", "Generic admin path", Severity.LOW, _admin_like),
    ("/manager/html", "Tomcat Manager", Severity.HIGH, _marker("Tomcat")),
    ("/jolokia/", "Jolokia JMX bridge", Severity.HIGH, _marker("jolokia")),
    ("/.env", "Env file", Severity.CRITICAL, lambda c, b: probe.is_dotenv(b)),
    ("/phpmyadmin/", "phpMyAdmin", Severity.MEDIUM, _marker("phpMyAdmin")),
    ("/swagger-ui.html", "Swagger UI v2", Severity.MEDIUM, _marker("swagger")),
    ("/swagger-ui/", "Swagger UI v3", Severity.MEDIUM, _marker("swagger")),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    base = target.origin + "/"
    try:
        for path, label, sev, validator in PATHS:
            url = urljoin(base, path.lstrip("/"))
            r = probe.verify_real(client, target, url, validator=validator)
            if r is None:
                continue
            ctype = r.headers.get("Content-Type", "")
            findings.append(Finding(
                module="framework_default",
                title=f"Endpoint default/admin terbuka: {label} ({path})",
                severity=sev,
                description=("Path framework/admin standar dapat diakses publik DAN kontennya "
                             "terverifikasi cocok (bukan halaman fallback SPA). Verifikasi apakah "
                             "perlu autentikasi atau seharusnya dimatikan di produksi."),
                target=url,
                evidence=f"HTTP {r.status_code}, Content-Type: {ctype}, konten terverifikasi",
                cwe="CWE-489",
                confidence="confirmed",
                remediation=("Matikan endpoint debug/management di produksi, atau "
                             "lindungi dengan basic auth + IP allowlist."),
            ))
    finally:
        client.close()
    return findings
