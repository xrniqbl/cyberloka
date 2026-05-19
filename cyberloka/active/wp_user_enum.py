"""WordPress user enumeration with active confirmation.

Mengonfirmasi username valid via 3 jalur paralel:
  1. /wp-json/wp/v2/users      -> JSON list user (tanpa auth)
  2. /?author=<n>              -> redirect ke /author/<slug>/
  3. /wp-login.php POST        -> error message berbeda untuk user valid vs invalid

Finding hanya muncul kalau MINIMAL 1 jalur menghasilkan username konkret.
Kalau target bukan WordPress (tidak ada /wp-login.php / /wp-json/), modul exit.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig


def _is_wordpress(client: HttpClient, base: str) -> bool:
    """Cepat: cek /wp-login.php atau generator meta tag."""
    r = client.get(urljoin(base, "wp-login.php"), allow_redirects=False)
    if r is not None and r.status_code in (200, 302) and "wordpress" in (r.text or "").lower():
        return True
    r = client.get(base)
    if r is not None and re.search(r'name="generator"\s+content="WordPress', r.text or "", re.I):
        return True
    return False


def _enum_via_rest(client: HttpClient, base: str) -> list[str]:
    r = client.get(urljoin(base, "wp-json/wp/v2/users?per_page=100"))
    if r is None or r.status_code != 200:
        return []
    try:
        data = r.json()
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    return [u.get("slug") or u.get("name") for u in data if isinstance(u, dict)]


def _enum_via_author_id(client: HttpClient, base: str, max_id: int = 5) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for uid in range(1, max_id + 1):
        r = client.get(urljoin(base, f"?author={uid}"), allow_redirects=False)
        if r is None:
            continue
        loc = (r.headers.get("Location") or "").lower()
        m = re.search(r"/author/([^/?#]+)", loc)
        if m:
            out.append((uid, m.group(1)))
            continue
        if r.status_code == 200:
            m2 = re.search(r"/author/([^/?#\"']+)", r.text or "")
            if m2:
                out.append((uid, m2.group(1)))
    return out


def _login_oracle(client: HttpClient, base: str, username: str) -> str | None:
    """Submit invalid password ke wp-login.php; pesan error berbeda kalau user
    valid ('password yang dimasukkan tidak benar') vs tidak valid ('username
    tidak terdaftar')."""
    r = client.post(
        urljoin(base, "wp-login.php"),
        data={"log": username, "pwd": "Cyberloka_invalid_xyz_123!", "wp-submit": "Log+In"},
        allow_redirects=False,
    )
    if r is None:
        return None
    body = (r.text or "").lower()
    if "password" in body and ("incorrect" in body or "tidak benar" in body):
        return "valid_user_wrong_password"
    if "is not registered" in body or "tidak terdaftar" in body or "unknown" in body:
        return "user_not_exist"
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.base_url
    client = HttpClient(config)
    try:
        if not _is_wordpress(client, base):
            return findings

        users_rest = _enum_via_rest(client, base)
        users_author = _enum_via_author_id(client, base)

        # Konfirmasi via login oracle untuk salah satu user
        confirmed: list[str] = []
        candidates: list[str] = list(filter(None, users_rest)) + [u for _, u in users_author]
        for u in list(dict.fromkeys(candidates))[:3]:
            if _login_oracle(client, base, u) == "valid_user_wrong_password":
                confirmed.append(u)

        if not (users_rest or users_author):
            return findings

        sev = Severity.MEDIUM if confirmed else Severity.LOW
        evidence = []
        if users_rest:
            evidence.append(f"REST API /wp-json/wp/v2/users: {users_rest[:10]}")
        if users_author:
            evidence.append(
                "?author=N -> "
                + ", ".join(f"id={i}:{u}" for i, u in users_author[:5])
            )
        if confirmed:
            evidence.append(f"Login-oracle CONFIRMED valid usernames: {confirmed}")

        findings.append(Finding(
            module="wp_user_enum",
            target=base,
            title=(
                f"WordPress user enumeration: {len(users_rest) + len(users_author)} username terbongkar"
                + (f" ({len(confirmed)} terkonfirmasi via login)" if confirmed else "")
            ),
            severity=sev,
            description=(
                "Daftar username admin/editor WordPress dapat di-enumerate publik "
                "tanpa autentikasi via REST API dan parameter ?author=. Ini mempersempit "
                "celah brute-force ke daftar username yang valid - attacker hanya perlu "
                "mencari password-nya. Sangat berbahaya bila digabung dengan endpoint "
                "wp-login.php tanpa rate-limit."
            ),
            evidence="\n".join(evidence),
            cwe="CWE-200",
            confidence="confirmed" if confirmed else "firm",
            urls=[urljoin(base, "wp-json/wp/v2/users"), urljoin(base, "?author=1")],
            remediation=(
                "1. Block /wp-json/wp/v2/users dari publik (firewall / plugin Disable REST API).\n"
                "2. Plugin 'Stop User Enumeration' untuk block ?author= probe.\n"
                "3. Pakai username unik (jangan 'admin'). Aktifkan 2FA.\n"
                "4. Plugin Limit Login Attempts + reCAPTCHA pada wp-login.php."
            ),
            references=[
                "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures",
                "https://wpscan.com/",
            ],
        ))
    finally:
        client.close()
    return findings
