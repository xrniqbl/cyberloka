"""Password policy audit.

Tujuan: memberi tester checklist untuk audit password policy. Tool ini
TIDAK mencoba registrasi dengan password lemah (itu butuh email valid &
captcha bypass). Sebagai gantinya, kita:

1. Discover halaman registrasi dari crawler (URL mengandung 'register', 'signup', 'daftar').
2. Parse JS hint client-side: cari pattern minlength="8", regex password,
   pesan "minimum 8 characters", dll.
3. Bila JS hanya validasi minimal/loose → laporkan (server mungkin trust client).
4. Daftar test manual yang harus tester lakukan (creds default, dictionary,
   length boundary).
"""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

REGISTER_URL_HINTS = ("register", "signup", "sign-up", "daftar", "createaccount", "join")

POLICY_PATTERNS = [
    (re.compile(r'minlength=["\']?(\d+)', re.I), "minlength"),
    (re.compile(r'data-min-length=["\'](\d+)', re.I), "data-min-length"),
    (re.compile(r'pattern=["\']([^"\']+)["\']', re.I), "pattern"),
]


MANUAL_TESTS = [
    "Coba register dengan password '123456', 'password', 'qwerty' — "
    "server harus reject (cek Have-I-Been-Pwned k-anonymity API).",
    "Test minimum length: register dengan password 1 karakter — harus reject.",
    "Test maximum length: 1000 karakter — server tidak boleh truncate diam-diam (sering bug).",
    "Test character set: register dengan emoji, unicode, karakter NULL — harus konsisten.",
    "Setelah register, login dengan password sama → cek apakah dihash di DB (bukan plaintext).",
    "Test password reuse: ganti password ke password lama (dalam history N terakhir) — "
    "harus reject (kecuali memang policy mengizinkan).",
    "Cek pesan error: 'password salah' vs 'user tidak ditemukan' — sebaiknya sama "
    "(generic) untuk mencegah account enumeration.",
    "Cek lockout: setelah N gagal login, akun di-lockout? Lock berbasis IP/account.",
    "Cek password expiration policy bila ada — terlalu sering paksa-ganti malah mendorong reuse.",
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    register_pages: list[str] = []

    discovered = getattr(target, "discovered", None)
    if discovered is not None:
        for ep in getattr(discovered, "endpoints", []):
            if any(h in ep.url.lower() for h in REGISTER_URL_HINTS):
                register_pages.append(ep.url)

    if not register_pages:
        return findings  # tidak ada halaman register → modul diam

    client = HttpClient(config)
    try:
        for url in register_pages[:3]:
            resp = client.get(url)
            if resp is None or not resp.text:
                continue
            body = resp.text

            min_lengths: list[int] = []
            patterns: list[str] = []

            for rgx, kind in POLICY_PATTERNS:
                for m in rgx.findall(body):
                    if kind in ("minlength", "data-min-length"):
                        try:
                            min_lengths.append(int(m))
                        except ValueError:
                            pass
                    elif kind == "pattern":
                        patterns.append(str(m)[:60])

            issues: list[str] = []
            sev = Severity.LOW
            if min_lengths:
                worst = min(min_lengths)
                if worst < 8:
                    issues.append(f"minlength={worst} (di bawah rekomendasi NIST 8 char)")
                    sev = Severity.HIGH
                elif worst < 12:
                    issues.append(f"minlength={worst} (rekomendasi modern: 12+ char)")
                    sev = Severity.MEDIUM
            if not min_lengths and not patterns:
                issues.append("tidak ada hint client-side validation untuk password")
                sev = Severity.MEDIUM

            if issues:
                findings.append(
                    Finding(
                        module="password_policy",
                        title=f"Halaman register {url}: kemungkinan password policy lemah",
                        severity=sev,
                        confidence="tentative",
                        description=(
                            "Tool men-inspect JS/HTML halaman register dan menemukan "
                            "indikasi password policy yang lemah / tidak ada. "
                            f"Issue: {'; '.join(issues)}. "
                            "Verifikasi server-side juga harus dilakukan (server bisa "
                            "lebih ketat dari client)."
                        ),
                        target=url,
                        evidence=f"min_lengths={min_lengths} patterns={patterns}",
                        cwe="CWE-521",
                        remediation=(
                            "Set minimum 12 karakter (NIST SP 800-63B 2024). Cek password "
                            "terhadap daftar password bocor (Have-I-Been-Pwned API). Jangan "
                            "paksa kompleksitas berlebihan (mis. wajib special char) — itu "
                            "mendorong user pakai pola yang sama."
                        ),
                        references=[
                            "https://pages.nist.gov/800-63-3/sp800-63b.html",
                            "https://haveibeenpwned.com/API/v3#PwnedPasswords",
                        ],
                    )
                )

        # Tambahkan checklist manual selalu jika ada halaman register
        findings.append(
            Finding(
                module="password_policy",
                title="Daftar test manual untuk password policy & login security",
                severity=Severity.INFO,
                description=(
                    "Beberapa aspek password policy harus di-test manual karena butuh "
                    "registrasi & login flow."
                ),
                target=target.base_url,
                evidence="\n".join(f"  - {t}" for t in MANUAL_TESTS),
            )
        )
    finally:
        client.close()
    return findings
