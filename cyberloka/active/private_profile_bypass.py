"""Private profile / privacy-setting bypass via API endpoint."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

PROFILE_API_HINTS = re.compile(
    r"/(api|v\d+)/(user|users|account|profile|me)/",
    re.I,
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings

    profile_apis: list[str] = []
    for u in s.urls + s.param_urls:
        if PROFILE_API_HINTS.search(u):
            profile_apis.append(u)

    # Tebak juga API umum
    for path in ["/api/users", "/api/v1/users", "/api/user/profile",
                 "/api/me", "/api/v1/me", "/api/profile"]:
        profile_apis.append(urljoin(target.origin + "/", path.lstrip("/")))

    if not profile_apis:
        return findings

    client = HttpClient(config)
    try:
        for url in profile_apis[:8]:
            # Endpoint utama
            r = client.get(url)
            if r is None or r.status_code >= 400:
                continue

            ctype = (r.headers.get("Content-Type") or "").lower()
            if "json" not in ctype:
                continue
            body = r.text or ""

            # Cek: apakah response memuat field yang seharusnya private?
            sensitive_fields = re.findall(
                r'"(email|phone|phone_number|hp|nomor|address|alamat|'
                r'ip_address|last_login|birth_date|tanggal_lahir|'
                r'is_private|private|hidden)"\s*:',
                body, re.I,
            )
            if sensitive_fields:
                # Periksa apakah ada user yang flag private tapi data masih ada
                if re.search(r'"is_private"\s*:\s*true', body, re.I) and \
                   re.search(r'"(email|phone|address|birth)"\s*:\s*"[^"]+', body, re.I):
                    findings.append(Finding(
                        module="private_profile_bypass",
                        target=url,
                        title="API mengembalikan data private meskipun is_private=true",
                        severity=Severity.HIGH,
                        description=(
                            "Endpoint API mengembalikan data sensitif (email, "
                            "phone, alamat) untuk user yang memiliki flag "
                            "`is_private: true`.\n\n"
                            "SKENARIO SERANGAN:\n"
                            "1. Korban mengaktifkan akun private dengan harapan "
                            "data pribadi disembunyikan.\n"
                            "2. Attacker akses API publik (via `curl` atau "
                            "browser dev tools).\n"
                            "3. Server tetap mengembalikan email/HP/alamat "
                            "korban karena privacy filter hanya berlaku di "
                            "FRONTEND, bukan di backend.\n"
                            "4. Data dijual / dipakai phishing / stalking.\n"
                            "5. Pelanggaran serius UU PDP No. 27/2022."
                        ),
                        evidence=(
                            f"Endpoint API : {url}\n"
                            f"Field sensitif terdeteksi : "
                            f"{', '.join(set(sensitive_fields))}\n"
                            f"is_private=true tapi data masih lengkap di response."
                        ),
                        cwe="CWE-359",
                        confidence="firm",
                        remediation=(
                            "LANGKAH PERBAIKAN:\n"
                            "1. Filter di SERVER, bukan di frontend:\n"
                            "   ```python\n"
                            "   if user.is_private and not requester.is_friend(user):\n"
                            "       data.pop('email', None)\n"
                            "       data.pop('phone', None)\n"
                            "       data.pop('birth_date', None)\n"
                            "   ```\n"
                            "2. Pakai SERIALIZER dengan whitelist field per-role "
                            "(Django REST: `fields` per ViewSet).\n"
                            "3. Per default, SEMBUNYIKAN semua field sensitif. "
                            "Hanya tampilkan kalau ada hubungan friend/follow.\n"
                            "4. Audit semua endpoint API — pastikan tidak ada "
                            "yang membypass logic ini.\n\n"
                            "VERIFIKASI:\n"
                            "Buat akun test, set ke private, lalu hit API dari "
                            "akun stranger. Response TIDAK boleh memuat email, "
                            "phone, alamat, atau tanggal lahir."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                        ],
                    ))
                    return findings
    finally:
        client.close()
    return findings
