"""MFA / 2FA bypass scanner.

Modul ini melengkapi `otp_check.py` (yang fokus pada OTP rate-limit dan
panjang kode) dengan **bypass test pada alur 2FA** secara umum.

Strategi probe (tanpa kredensial valid pun masih banyak temuan structural):

    1. **2FA endpoint discovery** — kandidat path:
        /verify, /verify-otp, /2fa, /mfa, /two-factor, /otp, /verify-token,
        /authenticate, /confirm, plus crawler-discovered.

    2. **Status-based forgery** — POST endpoint 2FA dengan field
       `verified=true`, `status=success`, `is_2fa_passed=1`. Server yang
       men-trust field ini akan langsung issue session.

    3. **HTTP method swap** — coba GET ke endpoint POST 2FA (`/verify`).
       Kalau membalas 200 dengan body sukses -> server tidak validasi
       method.

    4. **Empty / null OTP** — POST `code=`, `code=null`, `code=0`,
       `code=000000`. Kalau ada yang lolos -> validasi lemah.

    5. **Backup-code reuse** — POST endpoint backup code dengan kode dummy
       2x; bandingkan response.

    6. **Skip-step redirect** — kunjungi langsung URL post-2FA (mis.
       /dashboard, /home, /account) setelah login attempt yang seharusnya
       dijegal 2FA. Kalau membalas 200 + konten user-spesifik tanpa
       perlu OTP -> 2FA tidak ter-enforce.

    7. **Response tampering** — POST OTP yang salah, lihat response. Kalau
       memuat field `verified` yang bisa di-flip di JSON response (dipakai
       client-side) -> client-side trust antipattern.

Validasi & confidence:
    * Confirmed: marker bukti login dapat dilanjutkan tanpa OTP (status
      session cookie issued, atau body JSON `success: true`).
    * Tentative: response 200 dengan marker SUKSES tapi tidak yakin
      session-issued (validator gate akan reverify).

Karena modul ini destruktif berbeda-beda per app, semua POST hanya dengan
data fake yang tidak akan benar mengubah akun nyata.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state

MFA_HINTS = re.compile(
    r"(verify|otp|2fa|mfa|two[-_]?factor|authenticate|confirm|"
    r"backup[-_]?code)",
    re.I,
)
SUCCESS_MARKERS = (
    "verified", "success", "berhasil", "logged in", "login sukses",
    '"status":"ok"', '"verified":true', "redirect", "dashboard",
)
REJECT_MARKERS = (
    "invalid otp", "kode salah", "code expired", "kadaluwarsa",
    "invalid code", "wrong code", "maaf", "salah", "expired",
    "verification failed", "verifikasi gagal", "unauthorized",
    "401", "403", "must be logged", "csrf",
)

GENERIC_PATHS = [
    "verify", "verify-otp", "verify-2fa", "2fa", "mfa", "otp",
    "two-factor", "two-factor-auth", "authenticate", "confirm",
    "verify-token", "auth/verify", "auth/2fa", "api/verify",
    "api/2fa/verify", "api/mfa/verify", "api/auth/verify-otp",
    "api/auth/2fa", "verify-code", "api/verify-code",
    "user/2fa/verify", "user/verify",
]
POST_2FA_LANDING = [
    "dashboard", "home", "account", "profile", "user/me",
    "api/me", "api/user/profile", "settings",
]


def _candidates(target: Target, config: ScanConfig) -> list[str]:
    base = target.origin + "/"
    out: list[str] = [urljoin(base, p) for p in GENERIC_PATHS]
    state = get_state(config)
    if state:
        for u in state.urls + state.param_urls:
            if MFA_HINTS.search(u) and u not in out:
                out.append(u)
        for f in state.forms:
            action = f.get("action") or ""
            if MFA_HINTS.search(action) and action not in out:
                out.append(action)
    return out[:18]


def _accepted(status: int, body: str) -> bool:
    body_low = body.lower()
    if any(m in body_low for m in REJECT_MARKERS):
        return False
    if status not in (200, 201, 202):
        return False
    return any(m in body_low for m in SUCCESS_MARKERS)


def _exists(client: HttpClient, url: str) -> bool:
    h = client.head(url, allow_redirects=False)
    if h is None:
        return False
    return h.status_code not in (404, 410)


def _probe_status_forgery(client: HttpClient, url: str) -> Finding | None:
    """Inject field-status klaim sukses tanpa OTP valid."""
    payload = {
        "code": "000000", "otp": "000000",
        "verified": True, "is_verified": True,
        "is_2fa_passed": True, "status": "success",
        "mfa_status": "verified", "two_factor_pass": True,
    }
    r = client.post(url, data=payload)
    if r is None:
        return None
    if not _accepted(r.status_code, r.text or ""):
        return None
    return Finding(
        module="mfa_bypass",
        title=f"2FA dapat di-bypass via field status forgery di {url}",
        severity=Severity.CRITICAL,
        description=(
            "Endpoint verifikasi 2FA membalas SUKSES saat client mengirim "
            "field status (`verified=true`, `status=success`, dst.) tanpa "
            "OTP valid. Server tampak men-trust nilai dari client untuk "
            "menentukan status verifikasi."
        ),
        target=url,
        evidence=truncate(
            f"status={r.status_code} body={(r.text or '')[:160]}", 240),
        cwe="CWE-287",
        confidence="firm",
        remediation=(
            "Validasi OTP **server-side**: bandingkan input dengan "
            "OTP-aktif di DB/Redis (dengan TTL), bukan dengan field "
            "client. JANGAN baca `req.body.verified`. Pakai timing-safe "
            "compare, dan invalidasi OTP setelah pakai."
        ),
        extra={"reverify": {"status": (200, 201, 202), "marker": "verified",
                            "in_body": True, "method": "POST"}},
    )


def _probe_method_swap(client: HttpClient, url: str) -> Finding | None:
    r = client.get(url, allow_redirects=False)
    if r is None:
        return None
    if not _accepted(r.status_code, r.text or ""):
        return None
    return Finding(
        module="mfa_bypass",
        title=f"Endpoint 2FA membalas SUKSES untuk method GET ({url})",
        severity=Severity.HIGH,
        description=(
            "Verifikasi 2FA seharusnya hanya menerima POST. Server membalas "
            "OK pada GET — sering dipakai attacker untuk CSRF: "
            "`<img src='/verify-2fa?code=000000'>` di halaman attacker."
        ),
        target=url,
        evidence=f"GET {url} -> {r.status_code} body={r.text[:120] if r.text else ''!r}",
        cwe="CWE-352",
        confidence="firm",
        remediation=(
            "Tolak semua method selain POST. Implementasi CSRF token + "
            "SameSite=strict pada cookie session."
        ),
        extra={"reverify": {"status": (200, 201, 202), "method": "GET"}},
    )


def _probe_empty_otp(client: HttpClient, url: str) -> Finding | None:
    for body in (
        {"code": "", "otp": ""},
        {"code": "null", "otp": "null"},
        {"code": "0", "otp": "0"},
    ):
        r = client.post(url, data=body)
        if r is None:
            continue
        if _accepted(r.status_code, r.text or ""):
            return Finding(
                module="mfa_bypass",
                title=f"2FA bypass: server menerima OTP {body!r} sebagai valid",
                severity=Severity.CRITICAL,
                description=(
                    "Server membalas SUKSES untuk OTP kosong/null/`0`. "
                    "Validasi OTP tampak `if (otp == stored_otp)` saat "
                    "stored_otp juga belum ada/null untuk user tertentu — "
                    "klasik comparison-with-empty bypass."
                ),
                target=url,
                evidence=f"OTP={body!r} status={r.status_code}",
                cwe="CWE-287",
                confidence="firm",
                remediation=(
                    "Tolak input OTP kosong sebelum query DB. Pastikan "
                    "stored_otp tidak boleh NULL untuk user yang sedang "
                    "verifikasi (gunakan UNIQUE-NOT-NULL constraint dan "
                    "validate panjang OTP)."
                ),
                extra={"reverify": {"status": (200, 201, 202),
                                    "method": "POST"}},
            )
    return None


def _probe_skip_step(client: HttpClient, target: Target) -> Finding | None:
    """Kunjungi halaman post-2FA tanpa session valid. Kalau membalas konten
    user-spesifik (bukan redirect ke login), 2FA tidak ter-enforce di middleware."""
    base = target.origin + "/"
    for path in POST_2FA_LANDING:
        url = urljoin(base, path)
        r = client.get(url, allow_redirects=False)
        if r is None:
            continue
        # Skip kalau redirect ke login
        loc = (r.headers.get("Location") or "").lower()
        if r.status_code in (301, 302, 303, 307) and \
                ("login" in loc or "signin" in loc or "auth" in loc):
            continue
        if r.status_code != 200:
            continue
        body = (r.text or "").lower()
        # Kalau halaman menampilkan elemen user-spesifik (akun/dashboard/saldo),
        # padahal kita unauthenticated -> skip-step.
        markers = ("logout", "saldo", "balance", "welcome,", "halo,", "hai,",
                   "dashboard", "/api/me", "user_id")
        if any(m in body for m in markers) and "login" not in body[:300]:
            return Finding(
                module="mfa_bypass",
                title=f"Halaman post-2FA accessible tanpa autentikasi: {url}",
                severity=Severity.HIGH,
                description=(
                    "Halaman seperti `/dashboard` atau `/account` menampilkan "
                    "konten user-spesifik tanpa middleware autentikasi/2FA. "
                    "Bila halaman ini sebenarnya butuh login + 2FA, attacker "
                    "yang sudah lewat tahap 1 (password) bisa langsung skip."
                ),
                target=url,
                evidence=truncate(
                    f"HTTP {r.status_code} body_markers_found={[m for m in markers if m in body][:5]}",
                    240,
                ),
                cwe="CWE-306",
                confidence="tentative",
                remediation=(
                    "Pasang middleware enforce-MFA pada SEMUA halaman "
                    "internal. Jangan andalkan client redirect untuk gate "
                    "akses. Test: hit setiap halaman post-login tanpa "
                    "session — harus selalu redirect ke login."
                ),
                extra={"reverify": {"status": (200,), "marker": "logout",
                                    "in_body": True}},
            )
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for url in _candidates(target, config):
            if not _exists(client, url):
                continue
            for fn in (_probe_status_forgery, _probe_method_swap,
                       _probe_empty_otp):
                f = fn(client, url)
                if f:
                    findings.append(f)
                    break  # 1 finding per endpoint cukup

        # skip-step probe (tidak terikat endpoint 2FA)
        f = _probe_skip_step(client, target)
        if f:
            findings.append(f)
    finally:
        client.close()
    return findings
