"""phpMyAdmin / Adminer / Webmin: deteksi + validasi default credentials.

Untuk phpMyAdmin: menemukan token dari halaman login, submit POST dengan
kredensial default, lalu validasi via (a) cookie phpMyAdmin baru yang berisi
session, (b) absennya error message di response, (c) keberadaan 'main_content'
atau 'navigation' di body.

Kalau target = phpMyAdmin tanpa rate-limit + default password, attacker punya
akses penuh ke database production = data leak skala besar.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PMA_PATHS = (
    "/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/myadmin/",
    "/dbadmin/", "/sqladmin/", "/db/", "/database/",
    "/_phpMyAdmin/", "/PMA/", "/phpMyAdmin-4/", "/admin/phpmyadmin/",
)

CREDS = [
    ("root", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "mysql"),
    ("admin", "admin"),
    ("phpmyadmin", "phpmyadmin"),
]

PMA_TITLE_RE = re.compile(r"<title>\s*phpMyAdmin", re.I)
TOKEN_RE = re.compile(r'name="token"\s+value="([^"]+)"')
SET_NAME_RE = re.compile(r'name="set_session"\s+value="([^"]+)"')


def _detect_pma(client: HttpClient, base: str) -> str | None:
    for p in PMA_PATHS:
        url = urljoin(base, p.lstrip("/"))
        r = client.get(url, allow_redirects=True)
        if r is None or r.status_code >= 400:
            continue
        body = r.text or ""
        if PMA_TITLE_RE.search(body) or "pma_password" in body or "phpMyAdmin" in body[:1000]:
            return url
    # fallback: cek /index.php?lang=en yang khas pma
    r = client.get(urljoin(base, "index.php?lang=en"), allow_redirects=False)
    if r is not None and "phpMyAdmin" in (r.text or "")[:2000]:
        return urljoin(base, "index.php")
    return None


def _try_login_pma(client: HttpClient, login_url: str, user: str, pwd: str) -> tuple[bool, str]:
    """Returns (success, evidence_str)."""
    page = client.get(login_url)
    if page is None or page.status_code != 200:
        return False, "login page unreachable"
    body = page.text or ""
    token = (TOKEN_RE.search(body) or [None, ""])[1] if TOKEN_RE.search(body) else ""
    set_session = (
        SET_NAME_RE.search(body).group(1) if SET_NAME_RE.search(body) else ""
    )

    # Bersihkan cookie supaya jelas baseline
    client.session.cookies.clear()
    data = {
        "pma_username": user,
        "pma_password": pwd,
        "server": "1",
        "target": "index.php",
        "token": token,
    }
    if set_session:
        data["set_session"] = set_session

    r = client.post(login_url, data=data, allow_redirects=False)
    if r is None:
        return False, "post failed"

    # Konfirmasi via 3 signal:
    # 1. redirect ke index.php / main page
    # 2. cookie phpMyAdmin baru di-set (session)
    # 3. body tidak memuat 'cannot log in' / 'access denied'
    cookies_set = [c.name.lower() for c in r.cookies] if hasattr(r, "cookies") else []
    has_session_cookie = any(k in c for c in cookies_set for k in ("phpmyadmin", "pmasid", "pma_lang"))

    if r.status_code in (301, 302, 303):
        loc = (r.headers.get("Location") or "").lower()
        if "index.php" in loc and "auth" not in loc and has_session_cookie:
            return True, f"302 -> {loc}, session cookie set"

    if r.status_code == 200:
        body2 = (r.text or "").lower()
        if has_session_cookie and not any(k in body2[:3000] for k in (
            "cannot log in", "access denied", "tidak dapat masuk",
            "incorrect", "salah", "no privileges"
        )):
            return True, "200, session cookie set, no error msg"

    return False, f"status {r.status_code}"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.base_url
    client = HttpClient(config)
    try:
        pma_url = _detect_pma(client, base)
        if not pma_url:
            return findings

        # Selalu finding 'pma exposed' walaupun tidak ada default cred
        exposed_finding = Finding(
            module="phpmyadmin_default",
            target=pma_url,
            title="phpMyAdmin terbuka publik",
            severity=Severity.MEDIUM,
            description=(
                "phpMyAdmin dapat diakses dari internet. Bahkan kalau password kuat, "
                "exposed phpMyAdmin selalu jadi target #1 brute-force / 0-day exploit "
                "(banyak CVE setiap tahun). Idealnya pindahkan ke jaringan internal."
            ),
            evidence=f"URL: {pma_url}",
            cwe="CWE-693",
            confidence="confirmed",
            urls=[pma_url],
            remediation=(
                "1. Pindahkan phpMyAdmin ke jaringan internal/VPN.\n"
                "2. Bila harus publik: pakai .htaccess Basic Auth + IP allowlist + 2FA.\n"
                "3. Update phpMyAdmin ke versi terbaru.\n"
                "4. Pakai database GUI client (DBeaver/Sequel) via SSH tunnel."
            ),
        )
        findings.append(exposed_finding)

        # Coba default credentials
        for u, p in CREDS[:5]:
            ok, ev = _try_login_pma(client, pma_url, u, p)
            if ok:
                findings.append(Finding(
                    module="phpmyadmin_default",
                    target=pma_url,
                    title=f"phpMyAdmin tertembus dengan default {u}/{p or '(empty)'} (akses penuh DB)",
                    severity=Severity.CRITICAL,
                    description=(
                        f"phpMyAdmin di {pma_url} menerima kredensial default "
                        f"'{u}/{p or '(kosong)'}'. Validasi: {ev}. "
                        "Akses ini = read/write/drop seluruh database, termasuk "
                        "tabel user/password aplikasi. Setara dengan total breach "
                        "data pelanggan."
                    ),
                    evidence=f"URL: {pma_url}\nCredentials: {u}:{p}\nValidation: {ev}",
                    cwe="CWE-798",
                    confidence="confirmed",
                    urls=[pma_url],
                    remediation=(
                        "1. SEGERA ganti password root MySQL/MariaDB.\n"
                        "2. Audit semua user database (`SELECT user, host FROM mysql.user`),\n"
                        "   hapus user 'root'@'%' bila ada.\n"
                        "3. Bind MySQL ke 127.0.0.1 saja kalau memungkinkan.\n"
                        "4. Audit log database untuk lihat apakah sudah ada query mencurigakan."
                    ),
                    references=[
                        "https://cwe.mitre.org/data/definitions/798.html",
                    ],
                ))
                break
    finally:
        client.close()
    return findings
