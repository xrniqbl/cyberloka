"""CORS misconfiguration check."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        evil = "https://evil.example.com"
        resp = client.get(target.base_url, headers={"Origin": evil})
        if resp is None:
            return findings
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*" and acac == "true":
            sev, title = (
                Severity.CRITICAL,
                "CORS: wildcard origin + credentials (kombinasi terlarang)",
            )
        elif acao == evil and acac == "true":
            sev, title = (
                Severity.HIGH,
                "CORS: origin attacker dipantulkan dengan credentials",
            )
        elif acao == evil:
            sev, title = (
                Severity.MEDIUM,
                "CORS: origin attacker dipantulkan (tanpa credentials)",
            )
        elif acao == "*":
            sev, title = (
                Severity.LOW,
                "CORS: wildcard origin diset (tanpa credentials)",
            )
        else:
            return findings

        findings.append(
            Finding(
                module="cors",
                title=title,
                severity=sev,
                description=(
                    "Konfigurasi CORS yang salah memungkinkan situs lain membaca "
                    "data terotentikasi pengguna Anda dari API."
                ),
                target=target.base_url,
                evidence=(
                    f"Access-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Credentials: {acac}"
                ),
                remediation=(
                    "Whitelist origin secara eksplisit (cek `Origin` dan kembalikan "
                    "hanya jika ada di daftar). Jangan menggunakan wildcard `*` "
                    "bersamaan dengan `Allow-Credentials: true`."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                ],
            )
        )
    finally:
        client.close()
    return findings
