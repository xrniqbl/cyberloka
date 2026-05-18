"""Host header injection / cache poisoning probe."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

EVIL_HOST = "evil-cyberloka.example.com"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # Use the original URL but override Host header
        resp = client.get(
            target.base_url,
            headers={"Host": EVIL_HOST, "X-Forwarded-Host": EVIL_HOST},
            allow_redirects=False,
        )
        if resp is None:
            return findings

        body = resp.text or ""
        loc = resp.headers.get("Location", "")

        # Reflection in body or in redirect Location
        reflected_in_body = EVIL_HOST in body
        reflected_in_loc = EVIL_HOST in loc
        link_header = resp.headers.get("Link", "")
        reflected_in_link = EVIL_HOST in link_header

        if reflected_in_loc:
            findings.append(
                Finding(
                    module="host_header",
                    title="Host header injection: redirect ke domain attacker",
                    severity=Severity.HIGH,
                    description=(
                        "Server menggunakan Host header dari client untuk membentuk URL "
                        "redirect. Attacker bisa membuat link phishing yang mem-bypass "
                        "validasi domain."
                    ),
                    target=target.base_url,
                    evidence=f"Host injected: {EVIL_HOST}\nLocation: {loc}",
                    cwe="CWE-644",
                    remediation=(
                        "Gunakan canonical hostname yang dikonfigurasi di server, jangan "
                        "ambil dari Host/X-Forwarded-Host. Whitelist host yang sah "
                        "di reverse proxy."
                    ),
                    references=[
                        "https://portswigger.net/web-security/host-header",
                    ],
                )
            )
        elif reflected_in_body or reflected_in_link:
            findings.append(
                Finding(
                    module="host_header",
                    title="Host header injection: nilai dipantulkan ke response",
                    severity=Severity.MEDIUM,
                    description=(
                        "Host/X-Forwarded-Host attacker dipantulkan di body / Link header. "
                        "Bisa dipakai untuk cache poisoning bila ada CDN."
                    ),
                    target=target.base_url,
                    evidence=f"Host injected: {EVIL_HOST}\nReflected: body={reflected_in_body}, link={reflected_in_link}",
                    cwe="CWE-644",
                    remediation=(
                        "Validasi Host header di aplikasi & reverse proxy. "
                        "Set canonical absolute URL berdasarkan konfigurasi server, "
                        "bukan input user."
                    ),
                )
            )
    finally:
        client.close()
    return findings
