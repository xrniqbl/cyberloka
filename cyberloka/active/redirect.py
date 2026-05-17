"""Open redirect detection."""
from __future__ import annotations

from urllib.parse import urlparse

from cyberloka.active._helpers import iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

REDIRECT_PARAM_HINTS = ("next", "url", "redirect", "redir", "return", "returnto", "rurl", "dest", "destination", "continue", "to")
EVIL = "https://evil.example.com/cyberloka"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        url = target.base_url
        if "?" not in url:
            return findings
        for param, mutated in iter_param_urls(url, EVIL):
            if not any(h in param.lower() for h in REDIRECT_PARAM_HINTS):
                continue
            resp = client.get(mutated, allow_redirects=False)
            if resp is None:
                continue
            loc = resp.headers.get("Location", "")
            if not loc:
                continue
            host = urlparse(loc).hostname or ""
            if host.endswith("evil.example.com"):
                findings.append(
                    Finding(
                        module="redirect",
                        title=f"Open Redirect pada parameter `{param}`",
                        severity=Severity.MEDIUM,
                        description=(
                            "Server mengembalikan redirect ke domain eksternal arbitrer. "
                            "Bisa dipakai untuk phishing yang tampak resmi."
                        ),
                        target=mutated,
                        evidence=f"Location: {loc}",
                        cwe="CWE-601",
                        remediation=(
                            "Whitelist destinasi redirect. Bila perlu open redirect, "
                            "gunakan id internal yang dipetakan ke URL, atau verifikasi "
                            "host target ada di daftar yang diizinkan."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
                        ],
                    )
                )
    finally:
        client.close()
    return findings
