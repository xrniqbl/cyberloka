"""Detektor halaman/endpoint yang seharusnya protected tapi bisa diakses anonim.

Strategi non-destruktif:
- Probe daftar path "biasanya butuh login" tanpa kirim cookie/auth.
- Bila response 200 + body memuat data yang seharusnya privat (admin
  dashboard, daftar user, file user), laporkan.
- Ditambah: cek halaman/endpoint hasil crawler yang URL-nya admin-like
  (/admin, /dashboard, /panel, /api/admin) — apakah dapat diakses anonim?
- Ditambah: "default credentials" hint — bila login page bisa di-bypass
  dengan creds yang JELAS umum (admin/admin), kita NAMA-kan saja
  test-nya untuk dilakukan manual; kita tidak menebak password sendiri.

CATATAN: Tool ini TIDAK menebak password / brute-force. Ia hanya
mengevaluasi path yang seharusnya protected tapi diserve publik.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# Path yang BIASANYA butuh login. Bila return 200 anonim -> bermasalah.
# Diset konservatif supaya false-positive minim.
PROTECTED_PATHS = (
    # Admin-style
    "/admin", "/admin/", "/admin/dashboard", "/admin/users",
    "/admin/index.php", "/admin/login.php",
    "/administrator", "/administrator/",
    "/manage", "/manage/", "/management", "/manager",
    "/cpanel", "/control",
    "/dashboard", "/dashboard/admin",
    "/panel", "/panel/admin",
    "/console",
    # User profile (harusnya butuh auth)
    "/profile", "/account", "/akun", "/me", "/my-account",
    "/settings", "/pengaturan",
    # API
    "/api/admin", "/api/admin/users", "/api/admin/orders",
    "/api/users", "/api/v1/admin",
    "/api/me", "/api/profile", "/api/user",
    "/api/orders", "/api/transactions",
    # Internal tools
    "/internal", "/internal/", "/staff", "/backend",
    "/phpmyadmin/", "/pma/", "/adminer.php",
    "/jenkins/", "/grafana/", "/kibana/",
    "/server-status", "/server-info",
    "/metrics", "/actuator", "/actuator/health", "/actuator/env",
    "/_admin", "/_dashboard",
    # Document generators
    "/swagger-ui.html", "/swagger-ui/",
    "/api-docs", "/redoc",
)

# Marker yang menandakan halaman benar-benar berisi konten admin/user (bukan
# 404 styled 200, atau halaman login 200).
ADMIN_CONTENT_MARKERS = re.compile(
    r"(?:dashboard|administrator|manage users|user list|"
    r"daftar pengguna|kelola|panel admin|control panel|"
    r"phpmyadmin|grafana|kibana|jenkins|prometheus|"
    r"actuator|swagger ui|redoc|server-status|server-info|"
    r"<title>[^<]*(?:admin|dashboard|panel|console)[^<]*</title>)",
    re.IGNORECASE,
)
LOGIN_PAGE_MARKERS = re.compile(
    r"(?:log\s*in|sign\s*in|masuk|password|<input[^>]+type=[\"']password|login)",
    re.IGNORECASE,
)


def _classify(url: str, status: int, body: str, ctype: str) -> tuple[Severity | None, str]:
    """Klasifikasikan response. Return (severity, reason) atau (None, '') jika tidak menarik."""
    if status == 200 and body:
        # Halaman login bukan masalah (memang public). Skip.
        if LOGIN_PAGE_MARKERS.search(body[:5000]) and not ADMIN_CONTENT_MARKERS.search(body[:5000]):
            return None, ""
        if ADMIN_CONTENT_MARKERS.search(body[:5000]):
            return Severity.HIGH, "Halaman admin/dashboard ter-render anonim (200 + konten admin)."
        # JSON body 200 tanpa challenge → kandidat
        if "json" in ctype.lower() and len(body) > 50:
            return Severity.HIGH, "API response 200 dengan body JSON saat anonim."
        return Severity.LOW, "Path biasanya privat, return 200 tanpa otentikasi."
    if status in (401, 403):
        # Memang protected, BAGUS. Tidak laporkan.
        return None, ""
    if status in (302, 301):
        # Redirect — kalau ke login, OK; kalau ke admin lain, mungkin bocor URL
        return None, ""
    return None, ""


def _check_path(client: HttpClient, base: str, path: str) -> Finding | None:
    url = urljoin(base, path)
    resp = client.get(url, allow_redirects=False)
    if resp is None:
        return None
    body = resp.text or ""
    ctype = resp.headers.get("Content-Type", "")
    sev, reason = _classify(url, resp.status_code, body, ctype)
    if sev is None:
        return None

    # Tentukan severity final: kalau admin marker terlihat -> CRITICAL
    if "Halaman admin" in reason and resp.status_code == 200:
        sev = Severity.CRITICAL

    return Finding(
        module="auth_bypass",
        title=f"Halaman/endpoint dapat diakses tanpa login: {url}",
        severity=sev,
        description=(
            f"Path ini biasanya membutuhkan otentikasi, tetapi server mengembalikan "
            f"status {resp.status_code} pada request anonim. {reason}"
        ),
        target=url,
        evidence=(
            f"status={resp.status_code} content-type={ctype} "
            f"size={len(body)} snippet={truncate(body, 200)}"
        ),
        cwe="CWE-306",
        remediation=(
            "Tambahkan middleware otentikasi pada route ini. Pastikan:\n"
            "1) Anonymous request return 401 (untuk API) atau 302 ke login (untuk HTML).\n"
            "2) JANGAN andalkan obscurity nama path (mis. /admin12345).\n"
            "3) Gunakan framework guard (Express middleware, Django @login_required, "
            "Spring Security @PreAuthorize, dll)."
        ),
        references=[
            "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control/",
        ],
    )


def _check_crawler_admin_endpoints(client: HttpClient, target: Target) -> list[Finding]:
    """Cek endpoint hasil crawler yang URL-nya admin-like."""
    findings: list[Finding] = []
    discovered = getattr(target, "discovered", None)
    if discovered is None:
        return findings

    admin_pattern = re.compile(
        r"/(admin|administrator|dashboard|panel|console|manage|backend|"
        r"internal|staff|cpanel|control)(?:/|\?|$)",
        re.IGNORECASE,
    )
    seen: set[str] = set()
    for ep in getattr(discovered, "endpoints", []):
        if ep.method != "GET":
            continue
        if not admin_pattern.search(ep.url):
            continue
        if ep.url in seen:
            continue
        seen.add(ep.url)

        # Probe TANPA cookie/header auth (bypass session yang sudah login)
        # Kita pakai client baru session-less
        resp = client.get(ep.url, allow_redirects=False, cookies={})
        if resp is None:
            continue
        body = resp.text or ""
        ctype = resp.headers.get("Content-Type", "")
        sev, reason = _classify(ep.url, resp.status_code, body, ctype)
        if sev is None:
            continue
        if ADMIN_CONTENT_MARKERS.search(body[:5000]):
            sev = Severity.CRITICAL
        findings.append(
            Finding(
                module="auth_bypass",
                title=f"Admin endpoint dari crawler dapat diakses anonim: {ep.url}",
                severity=sev,
                description=(
                    "Endpoint dengan URL admin-style ditemukan crawler dan tetap "
                    f"return {resp.status_code} pada request tanpa cookie. {reason}"
                ),
                target=ep.url,
                evidence=f"status={resp.status_code} {truncate(body, 200)}",
                cwe="CWE-306",
                remediation=(
                    "Pasang auth guard di route admin. Test ulang dengan browser baru "
                    "(incognito) untuk konfirmasi."
                ),
            )
        )
    return findings


# Daftar test manual yang harus dilakukan tester (auth & access control yang tidak otomatis)
MANUAL_TESTS = [
    "Login dengan creds default umum: admin/admin, admin/password, root/root, "
    "admin/123456, administrator/administrator. JANGAN brute-force - ini hanya "
    "test creds 'placeholder' yang mungkin lupa di-disable.",
    "Force browse: catat semua URL setelah login admin, lalu coba akses URL itu "
    "dari incognito (anonim) - harus 401/302.",
    "Privilege escalation horizontal: login user A, akses URL/object milik user B.",
    "Privilege escalation vertical: login user biasa, akses URL admin.",
    "Token tanpa session: kirim request dengan Cookie: dihapus, Authorization: dihapus - "
    "endpoint sensitif harus tetap reject.",
    "Session fixation: login lalu cek apakah session ID berubah. Kalau tidak, "
    "fixation-able.",
    "Logout test: setelah logout, coba pakai cookie/token yang sama lagi - harus reject.",
    "Test endpoint internal yang mungkin tidak ter-link tapi exist: /internal, "
    "/_admin, /staging, /test, /backup, /old.",
    "API: cek apakah ada query param yang men-bypass auth (mis. ?debug=1, ?admin=true).",
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []

    # Buat client BARU tanpa cookies/auth bawaan supaya benar-benar anonim
    anon_config = ScanConfig(
        target=config.target,
        timeout=config.timeout,
        rate_limit=config.rate_limit,
        user_agent=config.user_agent,
        verify_tls=config.verify_tls,
        proxy=config.proxy,
        # cookies & headers SENGAJA dikosongkan
    )
    client = HttpClient(anon_config)
    try:
        for path in PROTECTED_PATHS:
            f = _check_path(client, target.origin + "/", path)
            if f:
                findings.append(f)

        # Cek endpoint admin-style hasil crawler
        findings.extend(_check_crawler_admin_endpoints(client, target))

        # Daftar test manual
        if findings:
            findings.append(
                Finding(
                    module="auth_bypass",
                    title="Daftar test manual untuk audit otentikasi & otorisasi",
                    severity=Severity.INFO,
                    description=(
                        "Tool sudah cek path/endpoint yang biasanya protected. Untuk audit "
                        "menyeluruh, lakukan test manual berikut."
                    ),
                    target=target.base_url,
                    evidence="\n".join(f"  - {t}" for t in MANUAL_TESTS),
                    remediation=(
                        "Implementasi access control matrix yang jelas: untuk setiap "
                        "endpoint, definisikan siapa yang boleh akses (anonim, user, admin) "
                        "lalu test dengan akun di tiap level."
                    ),
                )
            )
    finally:
        client.close()

    # Dedup: kadang /admin & /admin/ menghasilkan finding ganda
    seen: set[tuple[str, str]] = set()
    out: list[Finding] = []
    for f in findings:
        # normalize trailing slash
        norm = f.target.rstrip("/")
        key = (f.title.split(":")[0], norm)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
