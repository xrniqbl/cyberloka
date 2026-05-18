"""Cookie scope audit (Domain too wide / Path too broad)."""
from __future__ import annotations

import tldextract

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url)
        if r is None:
            return findings
        ext = tldextract.extract(target.host)
        registered = f"{ext.domain}.{ext.suffix}"
        for c in r.cookies:
            problems = []
            cookie_domain = (c.domain or "").lstrip(".")
            if cookie_domain == registered and target.host != registered:
                problems.append(
                    f"Domain={cookie_domain} (apex) — cookie dikirim ke SEMUA subdomain"
                )
            if c.path == "/" and any(
                k in c.name.lower() for k in ("admin", "internal", "staff")
            ):
                problems.append("Path=/ untuk cookie internal — bocor ke seluruh app")
            if problems:
                findings.append(Finding(
                    module="cookie_scope", target=target.base_url,
                    title=f"Cookie `{c.name}` punya scope terlalu lebar",
                    severity=Severity.LOW,
                    description=("Cookie sesi/internal dikirim ke lebih banyak subdomain/path "
                                 "daripada yang seharusnya. Risiko: subdomain takeover atau "
                                 "XSS di subdomain bisa mencuri cookie utama."),
                    evidence="; ".join(problems),
                    cwe="CWE-1275",
                    remediation=("Set Domain hanya untuk hostname yang butuh, batasi Path "
                                 "(`/admin` saja kalau memang admin-only)."),
                ))
    finally:
        client.close()
    return findings
