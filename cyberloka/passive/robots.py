"""robots.txt and sitemap.xml inspection."""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for name, sev_when_found in (("robots.txt", Severity.INFO), ("sitemap.xml", Severity.INFO)):
            url = urljoin(target.origin + "/", name)
            resp = client.get(url, allow_redirects=False)
            if resp is None or resp.status_code != 200 or not resp.text:
                continue
            findings.append(
                Finding(
                    module="robots",
                    title=f"{name} ditemukan",
                    severity=sev_when_found,
                    description=(
                        f"{name} dapat memberi peta endpoint internal kepada attacker."
                    ),
                    target=url,
                    evidence=truncate(resp.text, 800),
                    remediation=(
                        "Jangan mengandalkan robots.txt sebagai 'security by obscurity'. "
                        "Path sensitif harus benar-benar di-protect dengan auth/authz."
                    ),
                )
            )

            if name == "robots.txt":
                # flag suspicious disallow entries that might leak admin paths
                interesting = [
                    line for line in resp.text.splitlines()
                    if line.lower().startswith("disallow:") and any(
                        kw in line.lower() for kw in ("admin", "backup", "private", "secret", "config", "internal", ".git")
                    )
                ]
                if interesting:
                    findings.append(
                        Finding(
                            module="robots",
                            title="robots.txt membocorkan path sensitif",
                            severity=Severity.LOW,
                            description=(
                                "Disallow entry memberi petunjuk lokasi path sensitif "
                                "yang justru ingin disembunyikan."
                            ),
                            target=url,
                            evidence="\n".join(interesting),
                            remediation=(
                                "Hapus entry sensitif dari robots.txt. Lindungi path "
                                "tersebut dengan otentikasi/otorisasi."
                            ),
                        )
                    )
    finally:
        client.close()
    return findings
