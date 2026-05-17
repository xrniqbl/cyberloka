"""Brute-force / rate-limit resistance test on a login endpoint.

This sends a small, capped batch of obviously-wrong credentials (10 requests
within ~5s) to verify that the server rate-limits or locks the account.
It does NOT attempt real password guessing.
"""
from __future__ import annotations

import time

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

MAX_ATTEMPTS = 10


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if not config.login_url:
        return findings
    client = HttpClient(config)
    try:
        statuses: list[int] = []
        bodies_len: list[int] = []
        start = time.monotonic()
        for i in range(MAX_ATTEMPTS):
            data = {
                config.login_user_field: config.login_test_user,
                config.login_pass_field: f"wrong-cyberloka-{i}",
            }
            resp = client.post(
                config.login_url,
                data=data,
                allow_redirects=False,
            )
            if resp is None:
                continue
            statuses.append(resp.status_code)
            bodies_len.append(len(resp.text or ""))
        elapsed = time.monotonic() - start

        if not statuses:
            return findings

        rate_limited = any(s in (429, 503, 403) for s in statuses)
        # If all attempts return same 200/302 -> probably no rate limit
        unique = set(statuses)
        no_lockout = (rate_limited is False) and len(statuses) >= MAX_ATTEMPTS - 1

        ev = (
            f"attempts={len(statuses)} elapsed={elapsed:.1f}s "
            f"statuses={statuses} unique={sorted(unique)}"
        )

        if rate_limited:
            findings.append(
                Finding(
                    module="rate_limit",
                    title="Rate limiting / lockout terdeteksi",
                    severity=Severity.INFO,
                    description=(
                        "Server merespon dengan 429/503/403 setelah beberapa percobaan login "
                        "yang gagal. Indikasi adanya pertahanan brute-force."
                    ),
                    target=config.login_url,
                    evidence=ev,
                )
            )
        elif no_lockout:
            findings.append(
                Finding(
                    module="rate_limit",
                    title="Endpoint login tidak menerapkan rate limiting",
                    severity=Severity.HIGH,
                    description=(
                        f"{MAX_ATTEMPTS} percobaan login gagal beruntun semua diterima. "
                        "Endpoint rentan terhadap brute-force / credential stuffing."
                    ),
                    target=config.login_url,
                    evidence=ev,
                    cwe="CWE-307",
                    remediation=(
                        "Implementasi rate-limit per IP & per akun (mis. 5 percobaan / 15 menit), "
                        "lockout sementara, CAPTCHA setelah N kegagalan, dan MFA. Monitor log "
                        "untuk pola credential stuffing."
                    ),
                    references=[
                        "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                    ],
                )
            )
    finally:
        client.close()
    return findings
