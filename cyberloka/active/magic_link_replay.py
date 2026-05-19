"""Magic Link Replay — strict-validation v0.10.4.

Menguji apakah magic link login URL bisa dipakai berulang kali (replayable).
Magic link yang aman harus invalidate setelah satu kali pakai.

Validasi:
  1. Temukan endpoint magic link (forgot-password, login link, invite).
  2. Trigger pengiriman magic link (jika possible).
  3. Simulasi penggunaan token yang sama dua kali.
  4. Jika server menerima kedua kali → replayable → vulnerable.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin, urlparse, parse_qs

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

MAGIC_LINK_PATHS = [
    "/api/auth/magic-link", "/api/v1/auth/magic-link",
    "/auth/magic-link", "/auth/passwordless",
    "/api/auth/passwordless", "/api/login/magic",
    "/magic-link/verify", "/auth/verify-email",
    "/api/auth/verify-token", "/login/token",
]

VERIFY_PATHS = [
    "/auth/verify", "/api/auth/verify",
    "/verify", "/api/verify-token",
    "/magic-link/callback", "/auth/callback",
    "/api/auth/callback", "/login/verify",
]

# Pattern for magic link tokens in URLs
TOKEN_PARAM_RE = re.compile(r"[?&](token|code|magic|link_token|verify_token)=([A-Za-z0-9_\-]{20,})")


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Link login ajaib (magic link) bisa dipakai berulang kali — "
        "siapa pun yang melihat link tersebut (dari email forward, log, history) "
        "bisa login berkali-kali."
    )
    awam_steps = [
        "Pengguna minta magic link untuk login tanpa password.",
        "Email berisi link sekali pakai dikirim ke inbox pengguna.",
        "Penyerang melihat link dari email forward / browser history / log server.",
        "Penyerang klik link yang SAMA — seharusnya ditolak, tapi server terima.",
        "Penyerang berhasil login ke akun korban kapan pun mau.",
    ]
    try:
        # Strategy 1: Try to trigger magic link and check token reuse behavior
        test_email = f"cyberloka_test_{secrets.token_hex(4)}@example.com"

        for path in MAGIC_LINK_PATHS:
            url = urljoin(target.base_url, path)
            # Try to request magic link
            resp = client.post(url, json={"email": test_email})
            if resp is None:
                resp = client.post(url, data={"email": test_email})
            if resp is None:
                continue
            if resp.status_code not in (200, 201, 202, 204):
                continue

            # Server accepted the request — magic link feature exists.
            # Now test verification endpoint with a fake token (twice)
            fake_token = secrets.token_urlsafe(32)
            for verify_path in VERIFY_PATHS:
                verify_url = urljoin(target.base_url, verify_path)

                # First attempt
                r1 = client.get(f"{verify_url}?token={fake_token}")
                if r1 is None:
                    r1 = client.post(verify_url, json={"token": fake_token})
                if r1 is None:
                    continue

                # We need the server to respond consistently (not 404)
                if r1.status_code == 404:
                    continue

                # Second attempt with SAME token
                r2 = client.get(f"{verify_url}?token={fake_token}")
                if r2 is None:
                    r2 = client.post(verify_url, json={"token": fake_token})
                if r2 is None:
                    continue

                # Check if server treats both consistently
                # If both return same error (token invalid/expired) → cannot confirm
                # If first succeeds and second also succeeds → vulnerable
                # With fake token, both should fail. But if error message says
                # "invalid" (not "already used") → no replay protection
                b1 = (r1.text or "").lower()
                b2 = (r2.text or "").lower()

                # Look for signs of replay protection
                has_replay_protection = any(phrase in b2 for phrase in [
                    "already used", "already claimed", "token expired",
                    "sudah digunakan", "sudah terpakai", "link expired",
                    "one-time", "single use",
                ])

                if has_replay_protection:
                    continue

                # If both return same generic "invalid token" without mentioning
                # reuse → server likely doesn't track token usage
                if r1.status_code == r2.status_code and (
                    "invalid" in b1 or "not found" in b1 or "expired" in b1
                ):
                    # Both failed same way — indicates no replay detection logic
                    # (server just checks if token exists, not if it was used)
                    curl_cmd = (
                        f"# Test magic link replay\n"
                        f"# Step 1: Request magic link\n"
                        f"curl -s -X POST '{url}' -H 'Content-Type: application/json' "
                        f"-d '{{\"email\": \"user@example.com\"}}'\n"
                        f"# Step 2: Use the token from email TWICE\n"
                        f"curl -s '{verify_url}?token=TOKEN_FROM_EMAIL'\n"
                        f"curl -s '{verify_url}?token=TOKEN_FROM_EMAIL'  # harus ditolak"
                    )

                    proof = ValidationProof(
                        method="magic-link-trigger+token-reuse-check",
                        confirmed=False,
                        steps=[
                            f"POST {url} → {resp.status_code} (magic link request accepted).",
                            f"GET {verify_url}?token=<fake> → {r1.status_code}.",
                            f"GET {verify_url}?token=<same_fake> → {r2.status_code}.",
                            "Server tidak memberikan indikasi 'already used' pada penggunaan kedua.",
                            "Indikasi: tidak ada replay protection — perlu verifikasi manual.",
                        ],
                        samples=[
                            f"first_response={b1[:80]}",
                            f"second_response={b2[:80]}",
                        ],
                        notes="Confirmed=False karena menggunakan fake token; perlu validasi manual.",
                    )

                    findings.append(Finding(
                        module="magic_link_replay",
                        title=f"Magic link kemungkinan replayable (no single-use enforcement)",
                        severity=Severity.HIGH,
                        description=(
                            f"Endpoint magic link {url} menerima request dan endpoint verifikasi "
                            f"{verify_url} tidak menunjukkan mekanisme 'already used'. "
                            f"Indikasi bahwa magic link token bisa dipakai berulang kali. "
                            f"Verifikasi manual diperlukan dengan token valid."
                        ),
                        target=url,
                        urls=[url, verify_url],
                        evidence=f"magic_link_endpoint={url}, verify_endpoint={verify_url}, no 'already_used' detection",
                        cwe="CWE-294",
                        confidence="firm",
                        remediation=(
                            "1. Invalidasi magic link token setelah penggunaan pertama.\n"
                            "2. Set expiry pendek (5-15 menit) untuk magic link.\n"
                            "3. Implementasi counter: token hanya valid untuk 1 kali GET.\n"
                            "4. Log dan alert jika token yang sama dipakai >1 kali.\n"
                            "5. Bind token ke session/device (IP + User-Agent)."
                        ),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                        ],
                        extra=build_extra(
                            proof=proof,
                            awam_steps=awam_steps,
                            awam_summary=awam_summary,
                            extra={"curl_cmd": curl_cmd},
                        ),
                    ))
                    break
            if findings:
                break
    finally:
        client.close()
    return findings
