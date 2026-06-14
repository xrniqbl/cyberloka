"""CSRF probe on follow/like/post/share endpoints."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

SOCIAL_HINTS = re.compile(
    r"/(api/)?(follow|unfollow|like|unlike|share|repost|retweet|"
    r"subscribe|block|report)/",
    re.I,
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings

    candidates = []
    for u in s.urls:
        if SOCIAL_HINTS.search(u):
            candidates.append(u)
    if not candidates:
        return findings

    client = HttpClient(config)
    bad = []
    try:
        for url in candidates[:6]:
            # Try POST without referer + without CSRF token
            r = client.post(
                url,
                headers={"Referer": "https://attacker.invalid/",
                         "Origin": "https://attacker.invalid"},
            )
            if r is None or r.status_code >= 500:
                continue
            # Sukses (200/204) tanpa CSRF reject = rentan
            if r.status_code in (200, 201, 204) and not any(
                k in (r.text or "").lower()
                for k in ("csrf", "forbidden", "unauthorized", "tidak diizinkan")
            ):
                bad.append((url, r.status_code))

        if bad:
            findings.append(Finding(
                module="social_csrf",
                target=target.base_url,
                title=f"{len(bad)} endpoint sosial menerima POST tanpa CSRF guard",
                severity=Severity.HIGH,
                confidence="tentative",
                description=(
                    "Endpoint follow/like/share/post tidak memvalidasi token "
                    "CSRF atau header Origin/Referer.\n\n"
                    "SKENARIO SERANGAN:\n"
                    "1. Attacker buat halaman jahat dengan tag image yang src-nya "
                    "menunjuk ke endpoint follow target (mis. img src=https://target.com/api/follow/attacker).\n"
                    "2. Korban yang sedang login mengunjungi halaman jahat "
                    "(via link spam / iklan / forum).\n"
                    "3. Browser otomatis kirim cookie sesi -> request follow "
                    "berhasil tanpa korban tahu.\n"
                    "4. Attacker auto-follow ribuan korban dalam 1 jam -> akun "
                    "attacker terlihat 'populer' & legit untuk scam berikutnya.\n"
                    "5. Variasi: mass-like spam content, mass-block musuh, "
                    "auto-post 'iklan' di profile korban."
                ),
                evidence="\n".join(
                    f"POST {u} -> {st} (dengan Origin attacker.invalid)"
                    for u, st in bad[:6]
                ),
                cwe="CWE-352",
                remediation=(
                    "LANGKAH PERBAIKAN:\n"
                    "1. Tambahkan CSRF token wajib di semua state-changing "
                    "request. Contoh form: tambahkan input hidden bernama "
                    "csrf_token yang nilainya di-render dari sesi server.\n"
                    "   Server validasi token cocok dengan session.\n"
                    "2. Set cookie sesi dengan SameSite=Lax (atau Strict). "
                    "Browser modern tidak akan kirim cookie ke cross-site POST.\n"
                    "3. Untuk API JSON: gunakan custom header (mis. "
                    "X-Requested-With: XMLHttpRequest) - header ini tidak "
                    "bisa di-set lewat tag form/img attack.\n"
                    "4. Validasi Origin header - tolak kalau bukan domain Anda.\n\n"
                    "VERIFIKASI:\n"
                    "Buat halaman HTML lokal dengan POST otomatis ke endpoint "
                    "follow + iframe + auto-submit. Buka dengan akun login. "
                    "Server harus REJECT dengan 403 Forbidden."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                ],
            ))
    finally:
        client.close()
    return findings
