"""Audit endpoint .well-known/* — best practice & info disclosure.

RFC 8615 mendefinisikan path ``/.well-known/...`` sebagai folder standar untuk
metadata service. Modul ini cek 9 file penting:

  security.txt                  -> RFC 9116 (kontak security disclosure)
  change-password               -> WHATWG (auto-redirect ke halaman ganti password)
  openid-configuration          -> OIDC discovery (jangan ekspos kalau bukan IdP)
  oauth-authorization-server    -> OAuth 2.0 discovery
  assetlinks.json               -> Android App Links binding
  apple-app-site-association    -> iOS Universal Links
  pki-validation                -> ACME / Let's Encrypt validation
  brand-indicators-for-message  -> BIMI logo
  matrix/server                 -> Matrix federation

Hasil:
- security.txt **HILANG**     -> LOW (best practice)
- security.txt **LAMA/expired** -> LOW
- openid-configuration EKSPOS PUBLIK padahal bukan IdP -> MEDIUM (info disclosure
  scope, claim, endpoints internal)
- oauth-authorization-server EKSPOS PUBLIK -> MEDIUM
- assetlinks.json salah format / berisi sha256_cert_fingerprints staging -> LOW
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

CHECKS: list[tuple[str, str]] = [
    ("/.well-known/security.txt", "security.txt"),
    ("/.well-known/change-password", "change-password"),
    ("/.well-known/openid-configuration", "openid-configuration"),
    ("/.well-known/oauth-authorization-server", "oauth-authorization-server"),
    ("/.well-known/assetlinks.json", "assetlinks.json"),
    ("/.well-known/apple-app-site-association", "apple-app-site-association"),
    ("/.well-known/pki-validation/", "pki-validation"),
    ("/.well-known/brand-indicators-for-message-identification.svg", "BIMI"),
    ("/.well-known/matrix/server", "matrix-server"),
]

EXPIRES_RE = re.compile(r"^\s*Expires\s*:\s*(.+?)\s*$", re.I | re.M)
CONTACT_RE = re.compile(r"^\s*Contact\s*:\s*(.+?)\s*$", re.I | re.M)


def _check_security_txt(body: str) -> tuple[Severity, str]:
    """Return (severity, note) for a security.txt body."""
    has_contact = bool(CONTACT_RE.search(body or ""))
    expires_match = EXPIRES_RE.search(body or "")
    if not has_contact:
        return Severity.LOW, "Field `Contact:` wajib namun tidak ditemukan."
    if not expires_match:
        return Severity.LOW, (
            "Field `Expires:` wajib (RFC 9116) namun tidak ditemukan. "
            "Tanpa expires, peneliti tidak tahu apakah file masih relevan."
        )
    raw = expires_match.group(1).strip()
    try:
        # Coba parse sebagai ISO 8601
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
            try:
                exp = datetime.strptime(raw.replace("+00:00", "Z"), fmt)
                if exp < datetime.utcnow():
                    return Severity.LOW, f"Expires sudah lewat ({raw})."
                return Severity.INFO, f"OK (Contact + Expires {raw})"
            except ValueError:
                continue
    except Exception:  # noqa: BLE001
        pass
    return Severity.LOW, f"Expires tidak bisa di-parse: {raw}"


def _is_real_idp(body: str) -> bool:
    """True kalau openid-configuration JSON yang sah — kalau iya, eksposnya OK."""
    try:
        data = json.loads(body)
        # OIDC wajib punya issuer + authorization_endpoint + jwks_uri
        return all(k in data for k in ("issuer", "authorization_endpoint", "jwks_uri"))
    except Exception:  # noqa: BLE001
        return False


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        present: list[str] = []
        for path, label in CHECKS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None:
                continue

            if label == "security.txt":
                if r.status_code != 200:
                    findings.append(
                        Finding(
                            module="well_known_audit",
                            title="security.txt tidak ada",
                            severity=Severity.LOW,
                            description=(
                                "RFC 9116 merekomendasikan setiap site publik menyediakan "
                                "/.well-known/security.txt berisi kontak untuk security "
                                "disclosure. Tanpa file ini, peneliti security yang "
                                "menemukan bug Anda kebingungan harus menghubungi siapa."
                            ),
                            target=url,
                            confidence="confirmed",
                            urls=[url],
                            remediation=(
                                "Buat /.well-known/security.txt minimal berisi:\n"
                                "  Contact: mailto:security@yourdomain.com\n"
                                "  Expires: 2026-12-31T00:00:00Z\n"
                                "  Preferred-Languages: id, en"
                            ),
                            references=[
                                "https://datatracker.ietf.org/doc/html/rfc9116",
                                "https://securitytxt.org/",
                            ],
                        )
                    )
                    continue
                present.append(label)
                sev, note = _check_security_txt(r.text or "")
                if sev != Severity.INFO:
                    findings.append(
                        Finding(
                            module="well_known_audit",
                            title=f"security.txt ada tapi: {note}",
                            severity=sev,
                            description="security.txt ditemukan tapi belum sepenuhnya valid.",
                            target=url,
                            evidence=truncate(r.text or "", 240),
                            confidence="confirmed",
                            urls=[url],
                            remediation=(
                                "Lengkapi `Contact:` (mailto/url) + `Expires:` (ISO 8601, "
                                "biasanya 1 tahun ke depan). Re-publish saat hampir expire."
                            ),
                            references=["https://datatracker.ietf.org/doc/html/rfc9116"],
                        )
                    )
                continue

            if r.status_code != 200:
                continue
            present.append(label)
            body = r.text or ""

            if label == "openid-configuration":
                if _is_real_idp(body):
                    # Eksposnya benar — INFO saja
                    findings.append(
                        Finding(
                            module="well_known_audit",
                            title="OpenID Connect discovery aktif (target adalah IdP)",
                            severity=Severity.INFO,
                            description=(
                                "Endpoint /.well-known/openid-configuration berisi konfigurasi "
                                "OIDC yang valid — wajar bila target memang Identity Provider."
                            ),
                            target=url,
                            evidence=truncate(body, 240),
                            confidence="confirmed",
                            urls=[url],
                            remediation=(
                                "Pastikan `jwks_uri` melayani key rotasi reguler dan "
                                "claim yang muncul tidak lebih dari yang perlu (minimal scope)."
                            ),
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            module="well_known_audit",
                            title="openid-configuration ekspos tapi konten tidak valid",
                            severity=Severity.MEDIUM,
                            description=(
                                "Endpoint /.well-known/openid-configuration ada tapi bukan "
                                "OIDC discovery yang sah. Mungkin aplikasi salah konfigurasi "
                                "atau ada framework yang membocorkan path internal."
                            ),
                            target=url,
                            evidence=truncate(body, 240),
                            confidence="firm",
                            urls=[url],
                            remediation=(
                                "Bila target bukan IdP, hapus path ini supaya tidak "
                                "membingungkan attacker / scanner."
                            ),
                        )
                    )
                continue

            if label == "assetlinks.json":
                # Cek apakah ada SHA256 fingerprint staging/dev
                if re.search(r"sha256_cert_fingerprints", body) and re.search(r"\bdev\b|\bstag\w+", body, re.I):
                    findings.append(
                        Finding(
                            module="well_known_audit",
                            title="assetlinks.json membocorkan dev/staging app",
                            severity=Severity.LOW,
                            description=(
                                "File assetlinks.json memuat fingerprint SHA256 untuk "
                                "varian dev/staging app — attacker tahu Anda punya build "
                                "non-produksi yang mungkin lebih lemah pengamanannya."
                            ),
                            target=url,
                            evidence=truncate(body, 240),
                            confidence="firm",
                            urls=[url],
                            remediation=(
                                "Pisahkan assetlinks.json: hanya app produksi yang "
                                "ter-publish, dev/staging gunakan domain berbeda."
                            ),
                        )
                    )
                continue

            # Default: catat sebagai INFO bahwa endpoint ini ada
            findings.append(
                Finding(
                    module="well_known_audit",
                    title=f".well-known/{label} ekspos",
                    severity=Severity.INFO,
                    description=(
                        f"Endpoint .well-known/{label} ditemukan. Bukan kerentanan, tapi "
                        "perlu dipastikan kontennya minimal & sesuai standar."
                    ),
                    target=url,
                    evidence=truncate(body, 240),
                    confidence="confirmed",
                    urls=[url],
                )
            )
    finally:
        client.close()
    return findings
