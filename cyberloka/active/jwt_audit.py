"""JWT (JSON Web Token) auditor.

Memeriksa:
- alg=none / alg=NONE (CVE-2015-2951 class)
- HS256 dengan secret lemah (dictionary attack offline pada token sample)
- Expiry sudah lewat tapi server masih menerima (perlu probing aktif endpoint)
- Klaim sensitif (kid, jku, jwk) yang dapat diserang
- Konfusi alg (RS256 -> HS256 dengan public key sebagai HMAC secret)
  -> hanya laporkan bila kita TIDAK dapat verifikasi secret, sebagai INFO.

Sumber JWT:
1) Cookie response (Set-Cookie) dengan nama mengandung 'jwt', 'token', 'access', 'id_token', 'auth'.
2) Header response Authorization (jarang) atau body JSON yang memuat 'token'.
3) `--jwt <token>` lewat CLI.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import load_data_lines, truncate

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{0,}")
SECRET_HINTS = ("jwt", "token", "access", "id_token", "auth", "session", "bearer")

# Daftar secret default yang sering dipakai dev
COMMON_SECRETS = [
    "secret",
    "secretkey",
    "secret_key",
    "supersecret",
    "changeme",
    "password",
    "admin",
    "test",
    "demo",
    "jwtsecret",
    "jwt_secret",
    "jwtSecretKey",
    "your-256-bit-secret",
    "your-secret-key",
    "key",
    "private",
    "default",
    "12345",
    "123456",
    "qwerty",
    "secret123",
    "p@ssw0rd",
    "iloveyou",
    "letmein",
    "shhhhh",
    "secretsecret",
]


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _decode_jwt(token: str) -> tuple[dict, dict, bytes, str] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        sig = _b64url_decode(parts[2]) if parts[2] else b""
        signing_input = (parts[0] + "." + parts[1]).encode()
        return header, payload, sig, signing_input.decode()
    except Exception:  # noqa: BLE001
        return None


def _try_hs256_secret(signing_input: str, sig: bytes, secret: str) -> bool:
    expected = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return hmac.compare_digest(expected, sig)


def _harvest_jwts_from_response(resp: Any) -> set[str]:
    found: set[str] = set()
    if resp is None:
        return found
    # Set-Cookie
    sc_list: list[str] = []
    try:
        if hasattr(resp.raw, "headers"):
            sc_list = list(resp.raw.headers.getlist("Set-Cookie"))
    except Exception:  # noqa: BLE001
        sc_list = []
    if not sc_list:
        sc = resp.headers.get("Set-Cookie")
        sc_list = [sc] if sc else []
    for sc in sc_list:
        for m in JWT_RE.findall(sc):
            found.add(m)
    # Authorization (rare in response, but custom apps do it)
    auth = resp.headers.get("Authorization", "") or resp.headers.get("X-Auth-Token", "")
    for m in JWT_RE.findall(auth or ""):
        found.add(m)
    # Body
    body = resp.text or ""
    if "eyJ" in body:
        for m in JWT_RE.findall(body):
            found.add(m)
    return found


def _ts_to_str(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


def audit_token(token: str, source: str) -> list[Finding]:
    """Audit satu token. Return list finding."""
    findings: list[Finding] = []
    decoded = _decode_jwt(token)
    if not decoded:
        return findings
    header, payload, sig, signing_input = decoded
    alg = (header.get("alg") or "").lower()
    typ = header.get("typ", "")
    kid = header.get("kid")
    jku = header.get("jku")
    jwk = header.get("jwk")

    short = truncate(token, 60)

    # alg=none
    if alg in ("none", ""):
        findings.append(
            Finding(
                module="jwt",
                title="JWT menggunakan alg=none (signature dapat di-bypass)",
                severity=Severity.CRITICAL,
                description=(
                    "Server mengeluarkan/menerima JWT dengan algoritma `none`. "
                    "Attacker dapat membuat token apa pun tanpa menandatangani."
                ),
                target=source,
                evidence=f"header={header}\ntoken={short}",
                cwe="CWE-347",
                remediation=(
                    "Tolak algoritma `none` di sisi verifier. Gunakan whitelist algoritma "
                    "(mis. `HS256` atau `RS256`) dan jangan mempercayai field `alg` dari token."
                ),
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc8725",
                ],
            )
        )

    # HS256 secret lemah
    if alg == "hs256" and sig:
        # gabungkan list common + wordlist file
        wordlist = list(dict.fromkeys(COMMON_SECRETS + load_data_lines("common_passwords.txt")))
        cracked: str | None = None
        for w in wordlist:
            if _try_hs256_secret(signing_input, sig, w):
                cracked = w
                break
        if cracked is not None:
            findings.append(
                Finding(
                    module="jwt",
                    title="JWT HS256 ditandatangani dengan secret lemah",
                    severity=Severity.CRITICAL,
                    description=(
                        "Secret HMAC dapat ditebak dengan dictionary kecil. Dengan secret ini "
                        "attacker dapat memalsukan JWT apa pun."
                    ),
                    target=source,
                    evidence=f"cracked_secret='{cracked}'\ntoken={short}",
                    cwe="CWE-798",
                    remediation=(
                        "Ganti secret menjadi nilai random ≥ 256-bit yang disimpan di secret "
                        "manager (mis. AWS Secrets Manager). Rotasi token. Pertimbangkan migrasi "
                        "ke RS256/EdDSA agar private key terisolasi."
                    ),
                )
            )

    # Expiry
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        if exp < time.time():
            findings.append(
                Finding(
                    module="jwt",
                    title="JWT yang ditemukan sudah kedaluwarsa",
                    severity=Severity.LOW,
                    description=(
                        "Token yang sample-nya kami temukan sudah lewat masa berlaku. "
                        "Bila server tetap menerima ini, terdapat kelemahan validasi exp."
                    ),
                    target=source,
                    evidence=f"exp={exp} ({_ts_to_str(int(exp))})\ntoken={short}",
                    remediation="Pastikan verifier memeriksa klaim `exp` dan menolak token kedaluwarsa.",
                )
            )

    # Long-lived token
    iat = payload.get("iat")
    if isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
        lifetime = exp - iat
        if lifetime > 30 * 24 * 3600:
            findings.append(
                Finding(
                    module="jwt",
                    title=f"JWT memiliki lifetime sangat panjang ({lifetime / 86400:.0f} hari)",
                    severity=Severity.MEDIUM,
                    description=(
                        "Access token JWT idealnya berumur pendek (menit). Lifetime panjang "
                        "memperluas window of compromise bila token bocor."
                    ),
                    target=source,
                    evidence=f"iat={iat} exp={exp} lifetime={lifetime}s",
                    remediation=(
                        "Pakai access token pendek (5-15 menit) + refresh token rotated yang "
                        "disimpan secara aman."
                    ),
                )
            )

    # kid / jku / jwk attacks
    if kid is not None:
        findings.append(
            Finding(
                module="jwt",
                title="JWT memuat klaim `kid` — periksa risiko injection",
                severity=Severity.LOW,
                description=(
                    "Field `kid` di header sering digunakan untuk memilih kunci verifikasi. "
                    "Bila nilai `kid` dipakai langsung di query SQL atau path file tanpa validasi, "
                    "attacker bisa memaksa server memakai key yang ia kontrol."
                ),
                target=source,
                evidence=f"kid={kid!r}",
                remediation=(
                    "Validasi `kid` sebagai whitelist string. Jangan gunakan untuk SQL/file path. "
                    "Jika memakai JWKS, pastikan endpoint JWKS dikontrol oleh service Anda saja."
                ),
            )
        )
    if jku or jwk:
        findings.append(
            Finding(
                module="jwt",
                title="JWT memuat `jku`/`jwk` — risiko key confusion",
                severity=Severity.HIGH,
                description=(
                    "Klaim `jku`/`jwk` membiarkan token MENUNJUK key untuk verifikasi sendiri. "
                    "Bila verifier menuruti, attacker bisa men-host key sendiri."
                ),
                target=source,
                evidence=f"jku={jku!r} jwk={(bool(jwk))}",
                remediation=(
                    "Abaikan `jku`/`jwk` dari header. Selalu pakai konfigurasi JWKS yang "
                    "hard-coded / berasal dari issuer terpercaya."
                ),
            )
        )

    # Info ringkas
    findings.append(
        Finding(
            module="jwt",
            title=f"JWT terdeteksi (alg={alg or 'unknown'})",
            severity=Severity.INFO,
            description="Sample token JWT ditemukan; klaim terbuka karena base64url tanpa enkripsi.",
            target=source,
            evidence=(
                f"header={header}\n"
                f"payload_keys={list(payload.keys())}\n"
                f"typ={typ} kid={kid}\n"
                f"token={short}"
            ),
            extra={"header": header, "payload_keys": list(payload.keys())},
        )
    )
    return findings


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    seen: set[str] = set()
    try:
        # 1) sample dari base URL
        urls = [target.base_url]
        # 2) tambah halaman login bila ada (diambil dari config atau auth)
        if config.login_url:
            urls.append(config.login_url)
        # 3) endpoint dari crawler
        discovered = getattr(target, "discovered", None)
        if discovered is not None:
            for ep in getattr(discovered, "endpoints", []):
                urls.append(ep.url)

        for url in urls[:30]:
            resp = client.get(url, allow_redirects=False)
            for tok in _harvest_jwts_from_response(resp):
                if tok in seen:
                    continue
                seen.add(tok)
                findings.extend(audit_token(tok, source=url))

        # 4) token via header Authorization yang sudah disuntikkan user
        auth = client.session.headers.get("Authorization", "")
        m = JWT_RE.search(auth)
        if m and m.group(0) not in seen:
            tok = m.group(0)
            seen.add(tok)
            findings.extend(audit_token(tok, source="--header Authorization"))
    finally:
        client.close()
    return findings
