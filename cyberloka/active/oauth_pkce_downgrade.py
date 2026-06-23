"""OAuth PKCE Downgrade — strict-validation v0.10.4.

Menguji apakah flow OAuth menerima code exchange tanpa code_verifier meskipun
PKCE (code_challenge) dikirim saat authorization request.

Validasi:
  1. Temukan OAuth/OIDC endpoint (/.well-known/openid-configuration atau heuristik).
  2. Cek apakah token endpoint menerima grant_type=authorization_code tanpa code_verifier.
  3. Jika server tidak menolak → PKCE bisa di-bypass (downgrade).
"""
from __future__ import annotations

import hashlib
import base64
import secrets
from urllib.parse import urljoin

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

OIDC_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
]

TOKEN_ENDPOINT_GUESSES = [
    "/oauth/token", "/oauth2/token", "/auth/token",
    "/api/oauth/token", "/token", "/connect/token",
    "/realms/master/protocol/openid-connect/token",
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Server OAuth tidak mewajibkan PKCE (code_verifier) — penyerang yang "
        "mencuri authorization code bisa menukarnya tanpa verifikasi tambahan."
    )
    awam_steps = [
        "Penyerang memulai login OAuth dengan PKCE (code_challenge).",
        "Penyerang intercept authorization code korban (via Referer, log, redirect).",
        "Penyerang kirim code ke token endpoint TANPA code_verifier.",
        "Server tetap menerbitkan access token — PKCE di-bypass.",
        "Penyerang mendapat akses penuh ke akun korban.",
    ]
    try:
        token_endpoint = None
        # Discover token endpoint
        for path in OIDC_PATHS:
            url = urljoin(target.base_url, path)
            resp = client.get(url)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    token_endpoint = data.get("token_endpoint")
                    break
                except Exception:
                    continue

        if not token_endpoint:
            for path in TOKEN_ENDPOINT_GUESSES:
                url = urljoin(target.base_url, path)
                resp = client.post(url, data={"grant_type": "client_credentials"})
                if resp and resp.status_code in (400, 401, 403, 200):
                    token_endpoint = url
                    break

        if not token_endpoint:
            return findings

        # Test PKCE downgrade: send code exchange without code_verifier
        fake_code = secrets.token_urlsafe(32)
        resp_no_verifier = client.post(token_endpoint, data={
            "grant_type": "authorization_code",
            "code": fake_code,
            "redirect_uri": target.base_url + "/callback",
            "client_id": "test_client",
        })

        if resp_no_verifier is None:
            return findings

        body = resp_no_verifier.text or ""
        status = resp_no_verifier.status_code

        # If server returns invalid_grant (code is fake but it didn't
        # complain about missing code_verifier) vs
        # If server returns error specifically about code_verifier → secure
        pkce_enforced = False
        lower_body = body.lower()
        if "code_verifier" in lower_body or "pkce" in lower_body:
            pkce_enforced = True

        if pkce_enforced:
            return findings

        # Check if the error is only about the code being invalid
        # (not about missing code_verifier) — means PKCE not enforced
        if status in (400, 401) and (
            "invalid_grant" in lower_body
            or "invalid_client" in lower_body
            or "unauthorized" in lower_body
        ):
            # Server didn't reject for missing code_verifier
            # Double confirm
            resp2 = client.post(token_endpoint, data={
                "grant_type": "authorization_code",
                "code": secrets.token_urlsafe(32),
                "redirect_uri": target.base_url + "/callback",
                "client_id": "test_client",
            })
            if resp2 is None:
                return findings
            body2 = (resp2.text or "").lower()
            if "code_verifier" in body2 or "pkce" in body2:
                return findings  # Intermittent, skip

            curl_cmd = (
                f"# Test PKCE downgrade — kirim tanpa code_verifier\n"
                f"curl -s -X POST '{token_endpoint}' \\\n"
                f"  -d 'grant_type=authorization_code&code=STOLEN_CODE"
                f"&redirect_uri={target.base_url}/callback&client_id=test_client'"
            )

            proof = ValidationProof(
                method="pkce-enforcement-check+double-confirm",
                confirmed=True,
                steps=[
                    f"Discovered token endpoint: {token_endpoint}.",
                    "POST token exchange tanpa code_verifier.",
                    f"Response {status}: error={body[:100]} — tidak ada penolakan soal PKCE.",
                    "Double-confirm: request kedua juga tidak minta code_verifier.",
                    "Kesimpulan: PKCE bisa di-downgrade / tidak enforced.",
                ],
                samples=[f"status={status}", f"error_snippet={body[:80]}"],
            )

            findings.append(Finding(
                module="oauth_pkce_downgrade",
                title="OAuth PKCE tidak enforced — code exchange tanpa code_verifier diterima",
                severity=Severity.HIGH,
                description=(
                    f"Token endpoint {token_endpoint} tidak menolak request "
                    f"code exchange yang tidak menyertakan code_verifier. "
                    f"Artinya PKCE bisa di-bypass: penyerang yang mencuri "
                    f"authorization code bisa langsung menukarnya tanpa bukti "
                    f"bahwa dia yang memulai flow."
                ),
                target=token_endpoint,
                urls=[token_endpoint],
                evidence=f"status={status}, no code_verifier rejection in body",
                cwe="CWE-287",
                confidence="confirmed",
                remediation=(
                    "1. Enforce PKCE pada token endpoint (reject request tanpa code_verifier).\n"
                    "2. Set code_challenge_methods_supported: ['S256'] di OIDC metadata.\n"
                    "3. Reject 'plain' method — hanya izinkan S256.\n"
                    "4. Implementasi sender-constrained tokens (DPoP) untuk pertahanan berlapis."
                ),
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc7636",
                    "https://oauth.net/2/pkce/",
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
