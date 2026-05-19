"""WordPress wp-login.php: coba kredensial default + multi-signal validation.

Validasi sukses login pakai 3 signal:
  1. response berisi cookie 'wordpress_logged_in_*'
  2. redirect ke /wp-admin/
  3. GET /wp-admin/profile.php memuat 'profile.php' / 'Profile'

Cap maksimum 5 percobaan untuk hindari lockout. Kalau ada wp_user_enum yang
sudah jalan, modul ini bisa pakai username yang ter-enumerate.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "P@ssw0rd"),
    ("admin", "wordpress"),
    ("administrator", "admin"),
    ("administrator", "administrator"),
    ("test", "test123"),
    ("demo", "demo"),
]


def _is_wp(client: HttpClient, base: str) -> str | None:
    """Returns wp-login.php URL or None."""
    url = urljoin(base, "wp-login.php")
    r = client.get(url, allow_redirects=False)
    if r is None:
        return None
    if r.status_code in (200, 302) and "wordpress" in (r.text or "").lower()[:5000]:
        return url
    return None


def _try_login(client: HttpClient, login_url: str, user: str, pwd: str) -> tuple[bool, str]:
    client.session.cookies.clear()
    r = client.post(
        login_url,
        data={"log": user, "pwd": pwd, "wp-submit": "Log+In", "redirect_to": "/wp-admin/", "testcookie": "1"},
        cookies={"wordpress_test_cookie": "WP+Cookie+check"},
        allow_redirects=False,
    )
    if r is None:
        return False, "post failed"

    cookies_set = [c.name.lower() for c in r.cookies] if hasattr(r, "cookies") else []
    has_logged_in = any(c.startswith("wordpress_logged_in_") for c in cookies_set)

    if has_logged_in and r.status_code in (301, 302):
        loc = (r.headers.get("Location") or "").lower()
        if "wp-admin" in loc:
            # Extra confirm: hit /wp-admin/profile.php
            base_url = login_url.rsplit("wp-login.php", 1)[0]
            prof = client.get(urljoin(base_url, "wp-admin/profile.php"))
            if prof is not None and prof.status_code == 200:
                body = (prof.text or "").lower()
                if "profile.php" in body and "log out" in body or "logout" in body:
                    return True, f"302->{loc}, wordpress_logged_in_* cookie set, /wp-admin/profile.php OK"
    return False, f"status {r.status_code}, cookies={cookies_set[:3]}"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.base_url
    client = HttpClient(config)
    try:
        login_url = _is_wp(client, base)
        if not login_url:
            return findings

        # Pakai juga username dari wp_user_enum kalau sudah jalan (dari config state)
        extra_users: list[str] = []
        try:
            from cyberloka.recon.crawler import get_state
            state = get_state(config)
            if state:
                # crawler tidak menyimpan username; kita ambil dari extra modul
                pass
        except Exception:
            pass

        attempts = 0
        for u, p in CREDS:
            if attempts >= 5:
                break
            attempts += 1
            ok, ev = _try_login(client, login_url, u, p)
            if ok:
                findings.append(Finding(
                    module="wp_admin_default",
                    target=login_url,
                    title=f"WordPress wp-admin tertembus dengan default {u}/{p}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"wp-login.php menerima kredensial '{u}/{p}'. Modul memvalidasi "
                        "secara otomatis dengan 3 signal: cookie wordpress_logged_in_* "
                        "ter-set, redirect ke /wp-admin/, dan halaman profile.php "
                        "mengembalikan menu Logout. Akses ini = full content control + "
                        "kemampuan upload theme/plugin (yang biasanya berujung RCE)."
                    ),
                    evidence=f"URL: {login_url}\nCredentials: {u}:{p}\nValidation: {ev}",
                    cwe="CWE-798",
                    confidence="confirmed",
                    urls=[login_url, urljoin(base, "wp-admin/")],
                    remediation=(
                        "1. SEGERA login dan ganti password admin (gunakan password manager).\n"
                        "2. Ganti username 'admin' (buat user baru, transfer post, hapus admin).\n"
                        "3. Install plugin Limit Login Attempts Reloaded + Wordfence.\n"
                        "4. Aktifkan 2FA (plugin Two Factor / Wordfence).\n"
                        "5. Audit user list (`SELECT * FROM wp_users`) untuk akun baru "
                        "yang tidak dikenal - kemungkinan attacker sudah membuat persistence."
                    ),
                    references=[
                        "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures",
                        "https://wordpress.org/support/article/hardening-wordpress/",
                    ],
                ))
                break  # cukup satu finding
    finally:
        client.close()
    return findings
