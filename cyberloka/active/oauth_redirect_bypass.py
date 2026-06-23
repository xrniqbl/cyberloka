"""OAuth redirect_uri whitelist bypass detection.

Auto-validation: probe variasi redirect_uri ke domain attacker. Bila server
mengembalikan 302 dengan Location berisi `attacker.example.com` atau code
parameter dialihkan ke domain non-resmi -> bypass terkonfirmasi.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

OAUTH_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/authorize",
    "/connect/authorize", "/o/authorize", "/openid/authorize",
    "/api/oauth/authorize",
]
ATTACKER = "https://attacker.cyblok-poc.invalid"
TRICKS = [
    ATTACKER,
    f"{ATTACKER}/callback",
    "//attacker.cyblok-poc.invalid",
    f"{{}}.attacker.cyblok-poc.invalid",   # diisi target host
    f"{{}}@attacker.cyblok-poc.invalid",   # @-trick
    f"https://attacker.cyblok-poc.invalid/{{}}",  # path trick
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    seen = False
    try:
        for path in OAUTH_PATHS:
            if seen:
                break
            base = urljoin(target.origin + "/", path.lstrip("/"))
            # Konfirmasi endpoint exists (200/302/400) dengan redirect_uri kosong
            probe = client.get(
                base + "?response_type=code&client_id=cyblok&redirect_uri=https://x.com",
                allow_redirects=False,
            )
            if probe is None or probe.status_code == 404:
                continue

            for tpl in TRICKS:
                redirect_uri = tpl.format(target.host) if "{}" in tpl else tpl
                full = (
                    f"{base}?response_type=code&client_id=cyblok"
                    f"&scope=openid&state=cyblok"
                    f"&redirect_uri={redirect_uri}"
                )
                r = client.get(full, allow_redirects=False)
                if r is None:
                    continue
                # Bypass confirmed: 302 ke attacker domain
                loc = r.headers.get("Location") or ""
                hp = urlparse(loc).hostname or ""
                if r.status_code in (301, 302, 303, 307) \
                        and "attacker.cyblok-poc" in hp.lower():
                    findings.append(Finding(
                        module="oauth_redirect_bypass",
                        title=f"OAuth redirect_uri whitelist rusak: {path}",
                        severity=Severity.HIGH,
                        description=(
                            "Endpoint OAuth menerima redirect_uri yang "
                            f"mengarah ke domain attacker (`{redirect_uri}`) "
                            "dan melakukan redirect (Location memuat domain "
                            "non-resmi). Code/access-token korban dapat "
                            "dikirim ke server attacker."
                        ),
                        target=full,
                        urls=[full],
                        evidence=(
                            f"GET {full} -> {r.status_code}; "
                            f"Location host = {hp}"
                        ),
                        cwe="CWE-601",
                        confidence="confirmed",
                        remediation=(
                            "Validasi redirect_uri dengan EXACT match ke "
                            "whitelist (string compare, bukan startswith/regex "
                            "loose). Tolak scheme selain https:// untuk "
                            "production client. Implementasikan PKCE (RFC 7636) "
                            "untuk mitigasi authorization-code interception."
                        ),
                        references=[
                            "https://datatracker.ietf.org/doc/html/rfc6749#section-10.6",
                            "https://datatracker.ietf.org/doc/html/rfc7636",
                        ],
                    ))
                    seen = True
                    break
    finally:
        client.close()
    return findings
