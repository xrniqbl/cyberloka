"""Kibana unauthenticated UI exposure."""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = ["/api/status", "/app/home", "/app/kibana"]
SIGNATURES = ("kbn-version", "kbn-name", "kibana_version", '"version":', "Kibana")


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code not in (200, 302):
                continue
            body = (r.text or "")[:8192]
            headers = " ".join(r.headers.keys())
            hit = any(sig in body for sig in SIGNATURES) \
                or "kbn-name" in headers.lower()
            if not hit:
                continue
            # Skip kalau redirect ke login -> berarti auth aktif
            if r.status_code == 302 and "login" in (r.headers.get("Location") or "").lower():
                continue
            findings.append(Finding(
                module="kibana_unauth",
                title="Kibana terbuka tanpa autentikasi",
                severity=Severity.HIGH,
                description=(
                    "Instance Kibana dapat diakses publik tanpa login. UI "
                    "Discover memberi akses ke seluruh index Elasticsearch "
                    "(log produksi, PII, audit trail)."
                ),
                target=url,
                urls=[url],
                evidence=f"GET {url} -> {r.status_code}; signature Kibana terdeteksi",
                cwe="CWE-306",
                confidence="confirmed",
                remediation=(
                    "Aktifkan X-Pack Security: `xpack.security.enabled=true`. "
                    "Pakai SSO (OIDC/SAML). Bind Kibana ke localhost dan "
                    "expose via reverse-proxy yang melakukan autentikasi."
                ),
                references=[
                    "https://www.elastic.co/guide/en/kibana/current/using-kibana-with-security.html",
                ],
            ))
            break
    finally:
        client.close()
    return findings
