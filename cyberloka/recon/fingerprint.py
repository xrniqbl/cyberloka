"""Technology fingerprint via headers and body markers."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# Map of header name -> finding label
HEADER_TECH = {
    "server": "Web Server",
    "x-powered-by": "Powered-By",
    "x-aspnet-version": "ASP.NET",
    "x-aspnetmvc-version": "ASP.NET MVC",
    "x-generator": "Generator",
    "x-drupal-cache": "Drupal",
    "x-magento-cache-debug": "Magento",
}

BODY_MARKERS = [
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(r"<meta name=\"generator\" content=\"(.+?)\"", re.I), "CMS Generator"),
    (re.compile(r"Joomla!", re.I), "Joomla"),
    (re.compile(r"Drupal\.settings", re.I), "Drupal"),
    (re.compile(r"laravel_session", re.I), "Laravel"),
    (re.compile(r"csrfmiddlewaretoken", re.I), "Django"),
    (re.compile(r"phpMyAdmin", re.I), "phpMyAdmin"),
    (re.compile(r"jQuery v?(\d+\.\d+\.\d+)", re.I), "jQuery"),
    (re.compile(r"react(?:-dom)?", re.I), "React"),
    (re.compile(r"vue(?:\.js)?", re.I), "Vue.js"),
    (re.compile(r"angular(?:\.js)?", re.I), "Angular"),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None:
            return findings
        techs: dict[str, str] = {}
        for hk, label in HEADER_TECH.items():
            v = resp.headers.get(hk)
            if v:
                techs[label] = v

        body = resp.text or ""
        for rgx, label in BODY_MARKERS:
            m = rgx.search(body)
            if m:
                techs[label] = m.group(0)[:120]

        if techs:
            findings.append(
                Finding(
                    module="fingerprint",
                    title="Technology fingerprint",
                    severity=Severity.INFO,
                    description=(
                        "Teknologi berikut terdeteksi dari header dan body. "
                        "Versi yang bocor memudahkan attacker mencari CVE."
                    ),
                    target=target.base_url,
                    evidence="\n".join(f"{k}: {v}" for k, v in techs.items()),
                    remediation=(
                        "Hapus / sembunyikan header `Server`, `X-Powered-By`, "
                        "`X-AspNet-Version`, dan meta `generator`. Lakukan "
                        "patching framework / CMS secara berkala."
                    ),
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                    ],
                    extra={"tech": techs},
                )
            )
    finally:
        client.close()
    return findings
