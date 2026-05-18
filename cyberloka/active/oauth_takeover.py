"""Pre-account-takeover via OAuth email-match probe."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

REGISTER_HINT = re.compile(r"register|signup|sign-?up|daftar", re.I)
OAUTH_HINT = re.compile(r"oauth|google|facebook|github|sso|continue-with", re.I)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings

    has_register = False
    has_oauth = False
    register_url = None
    for f in s.forms:
        action = (f.get("action") or "").lower()
        if REGISTER_HINT.search(action) and any(
            (i.get("type") or "").lower() == "password" for i in f["inputs"]
        ):
            has_register = True
            register_url = f["action"]
    for u in s.urls:
        if OAUTH_HINT.search(u):
            has_oauth = True
            break

    # Detect: site offers BOTH email/password register AND OAuth login
    if has_register and has_oauth:
        findings.append(Finding(
            module="oauth_takeover",
            target=target.base_url,
            title=(
                "Risiko pre-account-takeover: site menyediakan registrasi "
                "email+password DAN login OAuth"
            ),
            severity=Severity.MEDIUM,
            description=(
                "Site mengizinkan registrasi via email+password dan juga "
                "login OAuth (Google/Facebook/dsb). Kombinasi ini berisiko "
                "pre-account-takeover bila tidak ada email verification "
                "yang ketat.\n\n"
                "SKENARIO SERANGAN:\n"
                "1. Attacker tahu email korban (mis. korban@gmail.com).\n"
                "2. Attacker buka /register, isi email korban + "
                "password attacker. Akun TERBUAT.\n"
                "3. Korban suatu hari klik 'Login with Google' menggunakan "
                "akun Gmail-nya yang asli.\n"
                "4. Server lihat email match → MERGE login OAuth ke akun "
                "yang sudah ada (yang dibuat attacker).\n"
                "5. Korban kini login ke akun yang DIBUAT ATTACKER. Sesi "
                "korban dipakai untuk semua aksi, tapi attacker juga punya "
                "password sehingga tetap bisa masuk kapan saja.\n"
                "6. Attacker baca semua DM korban + post atas nama korban."
            ),
            evidence=(
                f"Form register   : {register_url}\n"
                f"OAuth ditemukan : {has_oauth}\n"
                "Verifikasi manual: register dengan email yang akan dipakai, "
                "lalu coba login OAuth dengan email sama dari akun lain."
            ),
            cwe="CWE-287",
            confidence="tentative",
            remediation=(
                "LANGKAH PERBAIKAN:\n"
                "1. Saat registrasi email+password, WAJIB EMAIL VERIFICATION "
                "sebelum akun aktif:\n"
                "   ```python\n"
                "   user = User.create(email, password, status='unverified')\n"
                "   send_verification_email(user)\n"
                "   # Tolak login sampai user klik link verifikasi.\n"
                "   ```\n"
                "2. Saat OAuth login dengan email yang sudah terdaftar:\n"
                "   - Kalau status user 'unverified' → INVALIDATE password "
                "lama, kirim warning email, tetap proses OAuth.\n"
                "   - Kalau status 'verified' → OAuth login normal "
                "(account legit milik user).\n"
                "3. Jangan auto-merge berdasarkan email saja — minta user "
                "konfirmasi (mis. masukkan password dulu untuk link akun).\n"
                "4. Kirim notifikasi email setiap kali method login baru "
                "ditambahkan.\n\n"
                "VERIFIKASI:\n"
                "1. Register dengan email test@example.com (jangan klik "
                "verifikasi).\n"
                "2. Coba login Google dengan email yang sama.\n"
                "3. Server harus DETEKSI inconsistency dan minta konfirmasi "
                "password / kirim email notif. TIDAK boleh langsung merge."
            ),
            references=[
                "https://www.microsoft.com/en-us/security/blog/2019/09/15/account-takeover/",
                "https://blog.detectify.com/best-practices/pre-hijacking-accounts/",
            ],
        ))
    return findings
