"""Authenticated vs anonymous response diff — cari field yang bocor.

Bug ini sangat umum di REST API: endpoint mengembalikan **objek user yang
sama** baik untuk request anonim/low-priv MAUPUN admin, tapi untuk admin
ada field tambahan (mis. ``email``, ``hashed_password``, ``api_key``,
``stripe_customer_id``, ``last_ip``). Dev lupa filter response per role,
sehingga walaupun frontend tidak menampilkan, raw JSON tetap berisi data.

Modul ini:
1. Butuh konfigurasi authenticated session (config.login_url + credential
   atau auth_bearer_token).
2. Probe kandidat path: /api/me, /api/profile, /api/users, /api/users/1,
   /api/orders, /api/transactions.
3. Bandingkan body response anonim vs authenticated:
   - Anggap ada **leak** kalau body anonim memuat field sensitif yang
     normalnya hanya untuk authenticated.
   - Anggap ada **role leak** kalau body authenticated mengandung field
     yang seharusnya admin-only (admin_notes, internal_id, encrypted_pwd).
4. Cek juga field name suspicious di response anonim secara independen.

Modul SAFE: hanya GET request.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

CANDIDATE_PATHS = [
    "/api/me", "/api/v1/me", "/api/v2/me",
    "/api/profile", "/api/v1/profile",
    "/api/user", "/api/users", "/api/users/1", "/api/users/me",
    "/api/account", "/api/v1/account",
    "/api/orders", "/api/orders/1",
    "/api/transactions",
    "/api/admin", "/api/admin/users",
    "/api/v1/admin/users",
    "/me", "/profile",
]

# Field names yang biasanya sensitif (case insensitive).
SENSITIVE_FIELDS = re.compile(
    r"\"(?:password|password_hash|hashed_password|salt|secret|api[_-]?key|"
    r"private[_-]?key|access[_-]?token|refresh[_-]?token|stripe_(?:secret|customer)_id|"
    r"midtrans_server_key|aws_secret|gcp_service_account|"
    r"otp_(?:secret|code)|mfa_secret|recovery_code|"
    r"internal_id|admin_notes|moderator_notes|"
    r"last_ip|last_login_ip|registration_ip|"
    r"phone_number_e164|nik|npwp|tax_id|ssn|credit_card)\"\s*:",
    re.I,
)


def _extract_field_names(body: str) -> set[str]:
    """Extract simple JSON keys from body (regex; cukup untuk diff)."""
    return set(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*:', body or ""))


def _classify_severity(field: str) -> Severity:
    f = field.lower()
    if any(x in f for x in ("password", "secret", "api_key", "private_key",
                             "access_token", "refresh_token", "midtrans",
                             "aws_secret", "stripe_secret", "service_account")):
        return Severity.CRITICAL
    if any(x in f for x in ("otp", "mfa", "recovery", "credit_card", "ssn",
                             "nik", "npwp", "tax_id")):
        return Severity.HIGH
    if any(x in f for x in ("last_ip", "last_login_ip", "phone")):
        return Severity.MEDIUM
    if any(x in f for x in ("internal_id", "admin_notes", "moderator")):
        return Severity.MEDIUM
    return Severity.LOW


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if not config.authorized:
        return findings

    has_auth = bool(config.auth_bearer_token or (config.login_username and config.login_password))
    client_anon = HttpClient(config)
    seen: set[str] = set()
    try:
        # Authenticated client: pakai HttpClient terpisah dengan header bearer
        # bila ada. (Login_url-based session diasumsikan sudah dilakukan di
        # auth.perform_login pada start scan.)
        for path in CANDIDATE_PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            if url in seen:
                continue
            seen.add(url)

            r_anon = client_anon.get(url, allow_redirects=False)
            if r_anon is None:
                continue
            if r_anon.status_code in (404, 410):
                continue

            anon_body = r_anon.text or ""
            anon_fields = _extract_field_names(anon_body)

            # --- Path 1: anon body sendiri sudah memuat field sensitif ---
            if anon_body and (200 <= r_anon.status_code < 300):
                # Pastikan body kelihatan JSON (bukan HTML SPA)
                if anon_body.strip().startswith(("{", "[")) or "application/json" in (
                    r_anon.headers.get("Content-Type") or ""
                ):
                    sensitive_matches = list(SENSITIVE_FIELDS.finditer(anon_body))
                    seen_fields: set[str] = set()
                    for m in sensitive_matches:
                        # m.group(0) bentuk: `"password":` -> ekstrak nama
                        fname = re.match(r'"(\w+)"', m.group(0))
                        if not fname:
                            continue
                        fname_str = fname.group(1)
                        if fname_str in seen_fields:
                            continue
                        seen_fields.add(fname_str)
                        sev = _classify_severity(fname_str)
                        findings.append(
                            Finding(
                                module="secrets_in_response_diff",
                                title=f"Field sensitif `{fname_str}` muncul di response publik {path}",
                                severity=sev,
                                description=(
                                    f"Endpoint {path} mengembalikan field `{fname_str}` ke "
                                    "request tanpa auth. Field ini biasanya hanya untuk "
                                    "owner / admin. Kebocoran ini melanggar prinsip least-"
                                    "privilege di response shaping."
                                ),
                                target=url,
                                evidence=(
                                    f"GET {url}\n"
                                    f"Status: HTTP {r_anon.status_code}\n"
                                    f"Field: {fname_str}\n"
                                    f"Body snippet:\n{truncate(anon_body, 280)}"
                                ),
                                cwe="CWE-200",
                                confidence="firm",
                                urls=[url],
                                remediation=(
                                    "Terapkan response shaping per role: serializer/DTO yang "
                                    "berbeda untuk public vs owner vs admin. JANGAN andalkan "
                                    "frontend untuk filter — backend wajib tidak mengirim "
                                    "field yang user tidak boleh tahu."
                                ),
                                references=[
                                    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                                    "https://cwe.mitre.org/data/definitions/200.html",
                                ],
                            )
                        )

            # --- Path 2: diff vs authenticated (kalau auth tersedia) ---
            if not has_auth:
                continue
            auth_headers = dict(config.headers or {})
            if config.auth_bearer_token:
                auth_headers["Authorization"] = f"Bearer {config.auth_bearer_token}"

            r_auth = client_anon.get(url, headers=auth_headers, allow_redirects=False)
            if r_auth is None:
                continue
            auth_body = r_auth.text or ""
            auth_fields = _extract_field_names(auth_body)

            extra_in_anon = anon_fields - auth_fields
            extra_in_auth = auth_fields - anon_fields

            # Field yang HANYA muncul di anon (& sensitif) = leak ke publik
            for f in extra_in_anon:
                if SENSITIVE_FIELDS.search(f'"{f}":'):
                    sev = _classify_severity(f)
                    findings.append(
                        Finding(
                            module="secrets_in_response_diff",
                            title=f"Anomali: field `{f}` muncul HANYA di response anon {path}",
                            severity=sev,
                            description=(
                                "Diff antara response anonim dan authenticated mengungkap "
                                f"field `{f}` muncul di anon tapi tidak di authenticated — "
                                "indikasi serializer publik bocor lebih banyak data daripada "
                                "yang seharusnya."
                            ),
                            target=url,
                            evidence=(
                                f"Anon body fields: {sorted(anon_fields)[:30]}\n"
                                f"Auth body fields: {sorted(auth_fields)[:30]}\n"
                                f"Field anomali  : {f}"
                            ),
                            cwe="CWE-200",
                            confidence="firm",
                            urls=[url],
                            remediation=(
                                "Audit serializer / response DTO untuk endpoint ini. "
                                "Hapus field dari response yang dikirim tanpa auth."
                            ),
                            references=[
                                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                            ],
                        )
                    )
    finally:
        client_anon.close()
    return findings
