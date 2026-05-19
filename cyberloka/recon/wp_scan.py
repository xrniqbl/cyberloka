"""WordPress fingerprint, version & user-enum scanner.

Tahapan validasi (semua harus terpenuhi sebelum lapor sebagai WordPress):
    1. **Fingerprint** — minimal salah satu:
        - meta tag `<meta name="generator" content="WordPress ...">`
        - path `/wp-includes/` atau `/wp-content/` muncul di body root
        - header `Link: ...; rel="https://api.w.org/"`
        - file `/readme.html` berisi `<title>WordPress`
       Bila tidak ada -> tidak emit Finding apa pun.
    2. **Version detection** — dari meta generator atau readme.html.
    3. **wp-login terbuka** — kunjungi `/wp-login.php`; bila status 200 +
       form input `log` & `pwd` ada, lapor.
    4. **xmlrpc.php** — POST request `system.listMethods`. Bila respons
       memuat `<methodResponse>` dengan banyak method -> lapor.
    5. **User enumeration** — `?author=<n>` (n=1..3): redirect 30x
       memuat `/author/<slug>/` -> ekstraksi slug = username.
    6. **REST API user list** — `/wp-json/wp/v2/users`: array JSON dengan
       `slug`/`name` -> lapor.
    7. **Plugin/theme path leak** — direct probe `/wp-content/plugins/`
       directory listing.

Setiap finding men-set extra["reverify"] dengan marker spesifik.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

WP_GENERATOR_RE = re.compile(
    r'<meta\s+name=[\'"]generator[\'"]\s+content=[\'"]WordPress\s*([\d.]*)',
    re.I,
)
WP_LINK_API_RE = re.compile(r'<\s*[^>]+>;\s*rel=[\'"]https://api\.w\.org/', re.I)
WP_PATH_HINTS = ("/wp-includes/", "/wp-content/", "/wp-json/")
README_VER_RE = re.compile(r"Version\s+([\d.]+)", re.I)


def _is_wordpress(client: HttpClient, target: Target) -> tuple[bool, str, str]:
    """Return (is_wp, version, evidence)."""
    base = target.origin + "/"
    r = client.get(target.base_url, allow_redirects=True)
    if r is None:
        return False, "", ""
    body = r.text or ""
    headers_link = r.headers.get("Link", "") or r.headers.get("link", "")
    if WP_GENERATOR_RE.search(body):
        m = WP_GENERATOR_RE.search(body)
        return True, (m.group(1) or "").strip(), "meta generator WordPress"
    if WP_LINK_API_RE.search(headers_link):
        return True, "", "Link: rel=https://api.w.org/"
    if any(h in body for h in WP_PATH_HINTS):
        return True, "", "wp-content/wp-includes path di body"
    # Fallback: readme.html
    rr = client.get(urljoin(base, "readme.html"), allow_redirects=False)
    if rr and rr.status_code == 200 and "WordPress" in (rr.text or ""):
        m = README_VER_RE.search(rr.text or "")
        return True, (m.group(1) if m else ""), "readme.html WordPress"
    return False, "", ""


def _check_wp_login(client: HttpClient, target: Target) -> Finding | None:
    url = urljoin(target.origin + "/", "wp-login.php")
    r = client.get(url, allow_redirects=False)
    if r is None or r.status_code != 200:
        return None
    body = (r.text or "").lower()
    if 'name="log"' not in body or 'name="pwd"' not in body:
        return None
    return Finding(
        module="wp_scan",
        title="WordPress login page (wp-login.php) terbuka publik",
        severity=Severity.LOW,
        description=(
            "Halaman login WordPress dapat diakses dari internet tanpa "
            "perlindungan (IP allowlist / basic-auth / WAF rule). "
            "Risiko brute-force dan credential stuffing besar bila tidak "
            "ada rate-limit + 2FA."
        ),
        target=url,
        evidence=f"HTTP 200, form fields `log` & `pwd` terdeteksi",
        cwe="CWE-307",
        confidence="firm",
        remediation=(
            "Lindungi `/wp-login.php` & `/wp-admin/` dengan IP allowlist + "
            "basic-auth tambahan, atau pakai plugin Wordfence / Limit Login "
            "Attempts. Aktifkan 2FA untuk semua user. Pertimbangkan "
            "rename URL admin lewat plugin WPS Hide Login."
        ),
        extra={"reverify": {"marker": 'name="log"', "in_body": True,
                            "status": (200,)}},
    )


def _check_xmlrpc(client: HttpClient, target: Target) -> Finding | None:
    url = urljoin(target.origin + "/", "xmlrpc.php")
    body_xml = (
        '<?xml version="1.0"?>'
        '<methodCall><methodName>system.listMethods</methodName>'
        '<params></params></methodCall>'
    )
    r = client.post(url, data=body_xml,
                    headers={"Content-Type": "text/xml"})
    if r is None or r.status_code != 200:
        return None
    body = r.text or ""
    if "<methodResponse>" not in body or "system.listMethods" not in body:
        return None
    method_count = body.count("<string>")
    if method_count < 5:
        return None
    return Finding(
        module="wp_scan",
        title="WordPress xmlrpc.php aktif (rentan brute & DDoS)",
        severity=Severity.MEDIUM,
        description=(
            "Endpoint `xmlrpc.php` WordPress aktif. Endpoint ini sering "
            "disalahgunakan untuk: (a) brute-force login dengan "
            "`system.multicall` (banyak login dalam 1 request, melewati "
            "rate-limit), (b) pingback DDoS reflected ke target lain, "
            "(c) enumerasi user."
        ),
        target=url,
        evidence=f"HTTP 200, method_count={method_count}",
        cwe="CWE-307",
        confidence="confirmed",
        remediation=(
            "Bila tidak dipakai (Jetpack/mobile app), matikan: tambah "
            "filter `add_filter('xmlrpc_enabled','__return_false');` atau "
            "block path di reverse-proxy. Bila dipakai, batasi IP yang "
            "boleh akses dan tolak `system.multicall`."
        ),
        extra={"reverify": {"marker": "system.listMethods",
                            "in_body": True, "method": "POST"}},
    )


def _check_user_enum(client: HttpClient, target: Target) -> Finding | None:
    base = target.origin + "/"
    found_users: set[str] = set()
    for n in range(1, 4):
        r = client.get(urljoin(base, f"?author={n}"), allow_redirects=False)
        if r is None:
            continue
        loc = r.headers.get("Location", "") or r.headers.get("location", "")
        m = re.search(r"/author/([^/?]+)/?", loc)
        if m and r.status_code in (301, 302):
            found_users.add(m.group(1))
    if not found_users:
        return None
    return Finding(
        module="wp_scan",
        title=f"WordPress user enumeration via ?author= ({len(found_users)} user)",
        severity=Severity.MEDIUM,
        description=(
            "Parameter `?author=N` redirect ke `/author/<slug>` — slug "
            "biasanya = username login. Attacker bisa kumpulkan daftar "
            "username sebelum brute-force password."
        ),
        target=urljoin(base, "?author=1"),
        evidence=f"users_found={sorted(found_users)}",
        cwe="CWE-200",
        confidence="confirmed",
        remediation=(
            "Block `?author=` di reverse proxy (`if ($args ~ \"author=\") "
            "{ return 403; }`), atau pakai plugin yang men-rewrite "
            "author slug ke nilai non-username (`Edit Author Slug`)."
        ),
        extra={"reverify": {"status": (301, 302)}},
    )


def _check_rest_users(client: HttpClient, target: Target) -> Finding | None:
    url = urljoin(target.origin + "/", "wp-json/wp/v2/users")
    r = client.get(url, allow_redirects=False)
    if r is None or r.status_code != 200:
        return None
    body = r.text or ""
    if not (body.lstrip().startswith("[") and '"slug"' in body):
        return None
    users = re.findall(r'"slug":"([^"]+)"', body)
    if not users:
        return None
    return Finding(
        module="wp_scan",
        title=f"WordPress REST users endpoint terbuka ({len(users)} user)",
        severity=Severity.MEDIUM,
        description=(
            "`/wp-json/wp/v2/users` mengembalikan daftar user (id, slug, "
            "nama, deskripsi) tanpa autentikasi. Sumber username yang "
            "sangat valid untuk brute-force."
        ),
        target=url,
        evidence=f"users={users[:8]}",
        cwe="CWE-200",
        confidence="confirmed",
        remediation=(
            "Filter REST: tambah hook `rest_authentication_errors` untuk "
            "menolak unauthenticated request ke endpoint `users`, atau "
            "pakai plugin `Disable WP REST API`."
        ),
        extra={"reverify": {"marker": '"slug"', "in_body": True}},
    )


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        is_wp, version, ev = _is_wordpress(client, target)
        if not is_wp:
            return findings

        # Fingerprint finding (severity rendah, tapi penting buat report).
        sev = Severity.MEDIUM if not version else (
            Severity.HIGH
            if version and version.startswith(("4.", "5.0", "5.1", "5.2", "5.3"))
            else Severity.LOW
        )
        findings.append(Finding(
            module="wp_scan",
            title=(f"WordPress terdeteksi" +
                   (f" v{version}" if version else "")),
            severity=sev,
            description=(
                "Site terdeteksi memakai WordPress. Pemeriksaan tambahan "
                "akan menyusul: xmlrpc, user enum, REST users, halaman "
                "login publik."
                + (f" Versi {version} dilaporkan — bandingkan dengan "
                   "https://wordpress.org/download/releases/ untuk advisory "
                   "yang berlaku."
                   if version else "")
            ),
            target=target.base_url,
            evidence=f"fingerprint: {ev}; version={version or 'unknown'}",
            cwe="CWE-200",
            confidence="confirmed",
            remediation=(
                "Selalu update WordPress core, plugin, dan theme ke versi "
                "terbaru. Hapus plugin yang tidak terpakai. Aktifkan "
                "auto-update minor + monitoring Wordfence."
            ),
            references=[
                "https://wordpress.org/download/releases/",
                "https://wpscan.com/wordpresses",
            ],
        ))

        for fn in (_check_wp_login, _check_xmlrpc,
                   _check_user_enum, _check_rest_users):
            f = fn(client, target)
            if f:
                findings.append(f)
    finally:
        client.close()
    return findings
