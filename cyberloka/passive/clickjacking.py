"""Clickjacking exposure check."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None:
            return findings
        xfo = resp.headers.get("X-Frame-Options", "").lower()
        csp = resp.headers.get("Content-Security-Policy", "").lower()
        if not xfo and "frame-ancestors" not in csp:
            findings.append(
                Finding(
                    module="clickjacking",
                    title="Halaman rentan clickjacking (tidak ada X-Frame-Options / frame-ancestors)",
                    severity=Severity.MEDIUM,
                    description=(
                        "Tanpa X-Frame-Options atau CSP frame-ancestors, halaman bisa di-iframe "
                        "oleh situs jahat dan korban dapat ditipu mengklik elemen tersembunyi."
                    ),
                    target=target.base_url,
                    remediation=(
                        "Set `X-Frame-Options: DENY` (atau `SAMEORIGIN`) DAN/atau "
                        "`Content-Security-Policy: frame-ancestors 'self'`."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Clickjacking",
                    ],
                )
            )
    finally:
        client.close()
    return findings
