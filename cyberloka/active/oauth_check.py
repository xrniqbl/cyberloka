"""OAuth/OIDC redirect_uri & state hygiene checks."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

OAUTH_PATTERN = re.compile(r"(authorize|oauth|/auth|/login)", re.I)


def _oauth_starts(target: Target, config: ScanConfig) -> list[str]:
    state = get_state(config)
    out = set()
    if state:
        for u in state.urls + state.param_urls:
            if OAUTH_PATTERN.search(u) and "redirect_uri" in u.lower():
                out.add(u)
    return list(out)[:5]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for url in _oauth_starts(target, config):
            parsed = urlparse(url)
            qs = dict(parse_qsl(parsed.query))
            problems = []
            if not qs.get("state"):
                problems.append("parameter `state` tidak ada (CSRF guard hilang)")
            if not (qs.get("code_challenge") and qs.get("code_challenge_method")):
                problems.append("PKCE tidak digunakan (`code_challenge`)")
            redirect_uri = qs.get("redirect_uri", "")
            if redirect_uri and redirect_uri.startswith("http://"):
                problems.append("`redirect_uri` lewat HTTP (bukan HTTPS)")
            if problems:
                findings.append(Finding(
                    module="oauth_check",
                    title="Konfigurasi OAuth/OIDC kurang aman",
                    severity=Severity.MEDIUM,
                    description=("Pemanggilan flow OAuth tidak mengikuti praktik terbaik. "
                                 "`state` mencegah CSRF; PKCE mencegah pencurian code; "
                                 "`redirect_uri` HTTPS mencegah token leak."),
                    target=url,
                    evidence="; ".join(problems),
                    cwe="CWE-352",
                    remediation=("Selalu kirim `state` (random per session), gunakan PKCE "
                                 "untuk public clients, dan whitelist exact-match `redirect_uri`."),
                    references=[
                        "https://datatracker.ietf.org/doc/html/rfc6749#section-10.12",
                        "https://datatracker.ietf.org/doc/html/rfc7636",
                    ],
                ))
    finally:
        client.close()
    return findings
