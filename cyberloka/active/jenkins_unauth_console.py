"""Jenkins unauth Script Console / Manage detection.

Auto-validation: GET /script + /manage. Validasi via string khas Jenkins
('Groovy script', 'Manage Jenkins', 'Jenkins-Crumb'). Tidak menjalankan
command apa pun (pengamanan extra) — hanya konfirmasi akses console.
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = [
    ("/script",     ["Groovy script", "scriptText", "Script Console"]),
    ("/manage",     ["Manage Jenkins", "Reload Configuration"]),
    ("/api/json",   ['"jobs"', '"useCrumbs"', '"slaveAgentPort"']),
    ("/computer/api/json", ['"computer"', '"displayName"']),
    ("/asynchPeople/api/json", ['"users"']),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    seen = False
    try:
        for path, signatures in PATHS:
            if seen:
                break
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            body = (r.text or "")[:8192]
            if not any(s in body for s in signatures):
                continue
            sev = Severity.CRITICAL if path == "/script" else Severity.HIGH
            findings.append(Finding(
                module="jenkins_unauth_console",
                title=f"Jenkins {path} dapat diakses tanpa autentikasi",
                severity=sev,
                description=(
                    "Endpoint Jenkins yang seharusnya dilindungi terbuka untuk "
                    "anonim. Khusus `/script` adalah Script Console — "
                    "akses = Remote Code Execution sebagai user Jenkins."
                ),
                target=url,
                urls=[url],
                evidence=f"GET {url} -> 200; signature match.",
                cwe="CWE-306",
                confidence="confirmed",
                remediation=(
                    "Aktifkan `Enable security` -> Project Matrix Authorization. "
                    "Dapatkan Anonymous = baca metadata saja (atau nol). "
                    "Pasang reverse-proxy basic-auth + IP allowlist untuk /script. "
                    "Audit /credentials dan rotate semua secret."
                ),
                references=[
                    "https://www.jenkins.io/doc/book/security/",
                    "https://www.jenkins.io/doc/book/managing/script-console/",
                ],
            ))
            if path == "/script":
                seen = True
    finally:
        client.close()
    return findings
