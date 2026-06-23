"""Refresh Token Rotation Check — strict-validation v0.10.4.

Menguji apakah refresh token bisa dipakai dua kali (no rotation).
Server yang aman HARUS menginvalidasi refresh token setelah dipakai sekali
dan menerbitkan yang baru (rotation).

Validasi:
  1. Temukan token endpoint.
  2. Jika config memiliki auth token → exchange untuk mendapat refresh token.
  3. Pakai refresh token untuk mendapat access token baru (pertama kali).
  4. Pakai refresh token YANG SAMA sekali lagi.
  5. Jika kedua kali berhasil → no rotation → vulnerable.
"""
from __future__ import annotations

import secrets
from urllib.parse import urljoin

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

TOKEN_PATHS = [
    "/oauth/token", "/oauth2/token", "/auth/token",
    "/api/auth/token", "/api/oauth/token",
    "/connect/token", "/token", "/api/token",
    "/api/v1/auth/refresh", "/api/auth/refresh",
    "/api/refresh-token", "/auth/refresh",
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Refresh token bisa dipakai berkali-kali tanpa di-rotate — "
        "jika token bocor, penyerang punya akses permanen ke akun korban."
    )
    awam_steps = [
        "Penyerang mencuri refresh token korban (dari XSS, log, atau device).",
        "Penyerang menukar refresh token ke server dan mendapat access token baru.",
        "Karena server tidak merotasi, token yang sama tetap valid.",
        "Korban tetap bisa login (tidak sadar tokennya dicuri).",
        "Penyerang punya akses permanen — logout korban tidak membantu.",
    ]
    try:
        token_endpoint = None
        # Discover token endpoint
        for path in TOKEN_PATHS:
            url = urljoin(target.base_url, path)
            resp = client.post(url, data={"grant_type": "refresh_token", "refresh_token": "test"})
            if resp and resp.status_code in (400, 401, 200):
                body = (resp.text or "").lower()
                if "invalid" in body or "expired" in body or "access_token" in body:
                    token_endpoint = url
                    break

        if not token_endpoint:
            return findings

        # We need a valid refresh token to test rotation.
        # Try to obtain one via password grant if credentials provided
        refresh_token = None
        if config.login_username and config.login_password:
            resp = client.post(token_endpoint, data={
                "grant_type": "password",
                "username": config.login_username,
                "password": config.login_password,
                "client_id": "cyberloka_test",
            })
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    refresh_token = data.get("refresh_token")
                except Exception:
                    pass

        if not refresh_token:
            # Try client_credentials (some servers issue refresh tokens)
            resp = client.post(token_endpoint, data={
                "grant_type": "client_credentials",
                "client_id": "cyberloka_test",
                "client_secret": "test",
            })
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    refresh_token = data.get("refresh_token")
                except Exception:
                    pass

        if not refresh_token:
            return findings

        # Test: use refresh token FIRST time
        resp1 = client.post(token_endpoint, data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        })
        if not resp1 or resp1.status_code != 200:
            return findings
        try:
            data1 = resp1.json()
            if "access_token" not in data1:
                return findings
        except Exception:
            return findings

        new_refresh = data1.get("refresh_token", "")

        # Test: use SAME refresh token SECOND time
        resp2 = client.post(token_endpoint, data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        })
        if not resp2 or resp2.status_code != 200:
            return findings  # Server rejected → rotation is working
        try:
            data2 = resp2.json()
            if "access_token" not in data2:
                return findings
        except Exception:
            return findings

        # If we get here, refresh token was accepted TWICE → no rotation
        curl_cmd = (
            f"# Test refresh token reuse (no rotation)\n"
            f"curl -s -X POST '{token_endpoint}' \\\n"
            f"  -d 'grant_type=refresh_token&refresh_token=<REFRESH_TOKEN>'\n"
            f"# Kirim dua kali — jika kedua kali berhasil, token tidak dirotasi."
        )

        proof = ValidationProof(
            method="double-use+response-check",
            confirmed=True,
            steps=[
                f"Token endpoint: {token_endpoint}.",
                "Refresh token dipakai pertama kali → access_token diterbitkan.",
                "Refresh token SAMA dipakai kedua kali → access_token lagi.",
                "Server tidak invalidasi refresh token lama → NO ROTATION.",
                f"New refresh token di resp1: {'ya' if new_refresh else 'tidak ada'}.",
            ],
            samples=[
                f"first_use_status={resp1.status_code}",
                f"second_use_status={resp2.status_code}",
            ],
        )

        findings.append(Finding(
            module="refresh_token_rotation",
            title="Refresh token tidak dirotasi — reuse tanpa batas",
            severity=Severity.HIGH,
            description=(
                f"Token endpoint {token_endpoint} menerima refresh token yang "
                f"sama untuk dipakai berkali-kali tanpa invalidasi. "
                f"RFC 6749 §10.4 merekomendasikan token rotation. "
                f"Tanpa rotation, token yang bocor memberikan akses permanen."
            ),
            target=token_endpoint,
            urls=[token_endpoint],
            evidence="refresh_token accepted twice without invalidation",
            cwe="CWE-613",
            confidence="confirmed",
            remediation=(
                "1. Implementasi refresh token rotation (RFC 6749 §10.4).\n"
                "2. Setiap kali refresh token dipakai, invalidasi yang lama, terbitkan yang baru.\n"
                "3. Implementasi reuse detection: jika token lama dipakai setelah rotasi, "
                "invalidasi SEMUA token di family tersebut.\n"
                "4. Set TTL pendek untuk refresh token (7-14 hari max).\n"
                "5. Bind refresh token ke device fingerprint."
            ),
            references=[
                "https://datatracker.ietf.org/doc/html/rfc6749#section-10.4",
                "https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation",
            ],
            extra=build_extra(
                proof=proof,
                awam_steps=awam_steps,
                awam_summary=awam_summary,
                extra={"curl_cmd": curl_cmd},
            ),
        ))
    finally:
        client.close()
    return findings
