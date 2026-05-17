"""OTP / 2FA endpoint audit.

Cek konfigurasi (bukan brute-force OTP):
1. Endpoint OTP request (kirim kode) — apakah rate-limited? Kirim 5 request
   dengan email random dalam <2 detik, cek ada 429.
2. Endpoint OTP verify — apakah menerima request tanpa session/token awal?
   (Bila iya, 2FA bisa dilewati.)
3. Pesan error apakah membocorkan info? (mis. "OTP salah, sisa 2 percobaan").
4. Daftar test manual untuk bypass OTP yang umum.
"""
from __future__ import annotations

import time

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

OTP_ENDPOINT_HINTS = (
    "otp", "verify", "2fa", "two-factor", "twofactor", "tfa",
    "authenticate", "verifycode", "verify-code", "send-otp", "request-otp",
    "kirim-otp", "verifikasi",
)

MANUAL_TESTS = [
    "OTP brute-force: kirim 1000 OTP guess (4-6 digit) — server harus rate-limit / lockout.",
    "OTP reuse: gunakan OTP yang sudah pernah dipakai (misal pakai 2x). Harus reject.",
    "OTP race: kirim 2 verify request bersamaan dengan OTP yang sama.",
    "OTP bypass status code: ubah HTTP response 401 → 200 di intercept (Burp). "
    "Frontend mungkin tidak verify body, hanya status.",
    "OTP bypass missing param: hapus field otp dari body, kirim. Server tidak boleh accept.",
    "OTP bypass null: kirim otp=null, otp='', otp=0, otp=true.",
    "OTP timing attack: ukur waktu response untuk OTP benar vs salah karakter pertama. "
    "Beda timing → server pakai string compare yang non-constant-time.",
    "OTP session-less: kirim verify-otp tanpa cookie/token request awal. "
    "Server harus reject (state-bound).",
    "OTP cross-account: minta OTP untuk akun A, pakai OTP itu di session akun B.",
    "Backup code abuse: bila ada backup code, cek apakah masing-masing single-use.",
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    discovered = getattr(target, "discovered", None)
    if discovered is None:
        return findings

    otp_eps: list[str] = []
    for ep in getattr(discovered, "endpoints", []):
        if any(h in ep.url.lower() for h in OTP_ENDPOINT_HINTS):
            otp_eps.append(ep.url)
    otp_eps = list(dict.fromkeys(otp_eps))

    if not otp_eps:
        return findings  # tidak ada OTP flow → diam

    client = HttpClient(config)
    try:
        # 1) Rate-limit test pada endpoint request-OTP
        for url in otp_eps[:3]:
            if not any(h in url.lower() for h in ("send", "request", "kirim", "generate")):
                continue
            statuses: list[int] = []
            t0 = time.monotonic()
            for i in range(5):
                resp = client.post(url, json={"email": f"test{i}@nowhere.invalid"}, allow_redirects=False)
                if resp is not None:
                    statuses.append(resp.status_code)
                if time.monotonic() - t0 > 5:
                    break
            ratelimited = any(s in (429, 503) for s in statuses)
            if statuses and not ratelimited:
                findings.append(
                    Finding(
                        module="otp_audit",
                        title=f"Endpoint OTP request tidak rate-limit: {url}",
                        severity=Severity.MEDIUM,
                        description=(
                            "5 request berurutan tidak ada yang return 429/503. Endpoint "
                            "request-OTP tanpa rate-limit memungkinkan SMS/Email bombing "
                            "(biaya & spam abuse) dan brute-force semantic."
                        ),
                        target=url,
                        evidence=f"5 requests dalam {time.monotonic() - t0:.1f}s, statuses={statuses}",
                        cwe="CWE-307",
                        remediation=(
                            "Rate-limit per email/phone/IP: max 1 OTP per 60 detik per "
                            "tujuan, max 5 OTP per IP per 15 menit, plus CAPTCHA setelah N."
                        ),
                    )
                )

        # 2) State-less verify endpoint (kirim verify tanpa request OTP dulu, tanpa cookie)
        for url in otp_eps[:3]:
            if not any(h in url.lower() for h in ("verify", "confirm", "verifikasi")):
                continue
            # Buat client fresh tanpa cookies
            fresh_cfg = ScanConfig(
                target=config.target,
                timeout=config.timeout,
                rate_limit=config.rate_limit,
                user_agent=config.user_agent,
                verify_tls=config.verify_tls,
                proxy=config.proxy,
            )
            fclient = HttpClient(fresh_cfg)
            try:
                resp = fclient.post(url, json={"otp": "000000", "code": "000000"}, allow_redirects=False)
            finally:
                fclient.close()
            if resp is None:
                continue
            # 200 / 400 dengan body yang bukan "session not found" → server menerima
            # request tanpa state preliminary
            body = (resp.text or "")[:500].lower()
            session_required_markers = (
                "session", "expired", "invalid request", "not authenticated",
                "no pending", "missing token", "unauthorized",
            )
            if resp.status_code != 401 and resp.status_code != 403:
                if not any(m in body for m in session_required_markers):
                    findings.append(
                        Finding(
                            module="otp_audit",
                            title=f"OTP verify endpoint mungkin tidak state-bound: {url}",
                            severity=Severity.MEDIUM,
                            confidence="tentative",
                            description=(
                                "Endpoint verify-OTP terlihat menerima request tanpa "
                                "session/token awal. Bila benar, attacker dapat brute-force "
                                "OTP tanpa harus mendapatkan session korban."
                            ),
                            target=url,
                            evidence=f"status={resp.status_code} body_excerpt={body[:200]}",
                            cwe="CWE-287",
                            remediation=(
                                "OTP verify HARUS terikat ke session yang sebelumnya request "
                                "OTP (mis. signed token). Server reject bila tidak ada "
                                "session/token preliminary."
                            ),
                        )
                    )

        # 3) Daftar test manual
        findings.append(
            Finding(
                module="otp_audit",
                title="Daftar test manual untuk OTP / 2FA",
                severity=Severity.INFO,
                description=(
                    "Endpoint OTP/2FA terdeteksi. Beberapa bypass tidak bisa dideteksi "
                    "otomatis dan harus di-test manual."
                ),
                target=target.base_url,
                evidence="\n".join(f"  - {t}" for t in MANUAL_TESTS),
            )
        )
    finally:
        client.close()
    return findings
