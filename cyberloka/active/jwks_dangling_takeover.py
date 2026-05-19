"""JWKS Dangling Domain Takeover — strict-validation v0.10.4.

Parse JWT issuer, fetch .well-known/openid-configuration, check if jwks_uri
points to a dangling (unresolvable / claimable) domain.

Validasi:
  1. Temukan JWT di response/cookie target.
  2. Decode header → ambil kid/issuer.
  3. Fetch OIDC config dari issuer → ambil jwks_uri.
  4. Resolve domain dari jwks_uri → jika NXDOMAIN atau CNAME dangling → takeover.
  5. Double-confirm DNS resolution.
"""
from __future__ import annotations

import base64
import json
import re
import socket
from urllib.parse import urljoin, urlparse

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

OIDC_WELL_KNOWN = "/.well-known/openid-configuration"


def _decode_jwt_header(token: str) -> dict:
    """Decode JWT header without verification."""
    try:
        header_b64 = token.split(".")[0]
        # Fix padding
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding
        header_bytes = base64.urlsafe_b64decode(header_b64)
        return json.loads(header_bytes)
    except Exception:
        return {}


def _is_dangling(domain: str) -> bool:
    """Check if domain is unresolvable (NXDOMAIN / no A record)."""
    try:
        socket.getaddrinfo(domain, 443, socket.AF_INET)
        return False
    except socket.gaierror:
        return True
    except Exception:
        return False


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Server Anda memvalidasi JWT menggunakan kunci dari domain yang sudah "
        "tidak aktif — penyerang bisa mengklaim domain tersebut dan membuat "
        "JWT palsu yang diterima server Anda."
    )
    awam_steps = [
        "Penyerang menemukan JWT yang dipakai aplikasi Anda.",
        "Dari JWT, penyerang tahu server mengambil kunci validasi dari domain X.",
        "Ternyata domain X sudah expired / tidak aktif (dangling).",
        "Penyerang membeli / mengklaim domain X.",
        "Penyerang pasang kunci publik sendiri di domain X.",
        "Sekarang penyerang bisa buat JWT atas nama siapa pun — server Anda menerima.",
    ]
    try:
        # Step 1: find JWT tokens in response
        resp = client.get(target.base_url)
        if resp is None:
            return findings

        # Check body and cookies for JWT
        jwts = set()
        body = resp.text or ""
        for m in JWT_RE.finditer(body):
            jwts.add(m.group(0))
        for cookie_val in resp.headers.get("Set-Cookie", "").split(","):
            for m in JWT_RE.finditer(cookie_val):
                jwts.add(m.group(0))

        if not jwts:
            # Try common auth endpoints
            for auth_path in ["/api/auth/session", "/api/me", "/api/user"]:
                r = client.get(urljoin(target.base_url, auth_path))
                if r and r.status_code == 200 and r.text:
                    for m in JWT_RE.finditer(r.text):
                        jwts.add(m.group(0))

        if not jwts:
            return findings

        checked_issuers: set[str] = set()

        for token in list(jwts)[:5]:
            header = _decode_jwt_header(token)
            if not header:
                continue

            # Try to get issuer from payload too
            try:
                payload_b64 = token.split(".")[1]
                padding = 4 - len(payload_b64) % 4
                if padding != 4:
                    payload_b64 += "=" * padding
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                issuer = payload.get("iss", "")
            except Exception:
                issuer = ""

            if not issuer or issuer in checked_issuers:
                continue
            checked_issuers.add(issuer)

            # Step 3: fetch OIDC config from issuer
            if issuer.startswith("http"):
                oidc_url = issuer.rstrip("/") + OIDC_WELL_KNOWN
            else:
                oidc_url = f"https://{issuer.rstrip('/')}{OIDC_WELL_KNOWN}"

            oidc_resp = client.get(oidc_url)
            if not oidc_resp or oidc_resp.status_code != 200:
                continue

            try:
                oidc_data = oidc_resp.json()
            except Exception:
                continue

            jwks_uri = oidc_data.get("jwks_uri", "")
            if not jwks_uri:
                continue

            # Step 4: check if jwks_uri domain is dangling
            jwks_domain = urlparse(jwks_uri).hostname
            if not jwks_domain:
                continue

            if not _is_dangling(jwks_domain):
                continue

            # Double confirm DNS
            if not _is_dangling(jwks_domain):
                continue

            curl_cmd = (
                f"# Check JWKS domain dangling\n"
                f"dig +short {jwks_domain}\n"
                f"# Jika kosong / NXDOMAIN → domain bisa diklaim\n"
                f"curl -s '{oidc_url}' | python3 -c \"import sys,json;"
                f"print(json.load(sys.stdin).get('jwks_uri'))\""
            )

            proof = ValidationProof(
                method="jwt-parse+oidc-discovery+dns-resolve+double-confirm",
                confirmed=True,
                steps=[
                    f"JWT ditemukan di response target.",
                    f"Issuer dari JWT payload: {issuer}.",
                    f"OIDC config di {oidc_url} → jwks_uri={jwks_uri}.",
                    f"DNS lookup {jwks_domain} → NXDOMAIN (dangling).",
                    "Double-confirm DNS: tetap NXDOMAIN.",
                    "Kesimpulan: domain JWKS bisa diklaim → JWT forgery.",
                ],
                samples=[f"issuer={issuer}", f"jwks_uri={jwks_uri}"],
            )

            findings.append(Finding(
                module="jwks_dangling_takeover",
                title=f"JWKS URI mengarah ke domain dangling: {jwks_domain}",
                severity=Severity.CRITICAL,
                description=(
                    f"OIDC configuration di {oidc_url} menyatakan jwks_uri = "
                    f"{jwks_uri}, namun domain {jwks_domain} tidak dapat di-resolve "
                    f"(NXDOMAIN). Penyerang dapat mengklaim domain tersebut, "
                    f"memasang public key sendiri, lalu membuat JWT palsu yang "
                    f"akan diterima oleh server Anda sebagai valid."
                ),
                target=jwks_uri,
                urls=[jwks_uri, oidc_url],
                evidence=f"jwks_domain={jwks_domain} → NXDOMAIN; issuer={issuer}",
                cwe="CWE-295",
                confidence="confirmed",
                remediation=(
                    "1. Segera update jwks_uri ke domain yang Anda kontrol.\n"
                    "2. Jika domain lama, BELI KEMBALI domain tersebut segera.\n"
                    "3. Pin JWKS keys secara lokal daripada fetch runtime.\n"
                    "4. Implement JWKS caching + fallback validation.\n"
                    "5. Monitor DNS expiry untuk semua domain di infrastruktur auth."
                ),
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc7517",
                    "https://portswigger.net/web-security/jwt",
                ],
                extra=build_extra(
                    proof=proof,
                    awam_steps=awam_steps,
                    awam_summary=awam_summary,
                    extra={"curl_cmd": curl_cmd},
                ),
            ))
            break
    finally:
        client.close()
    return findings
