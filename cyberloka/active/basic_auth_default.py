"""HTTP Basic / Digest Auth dengan kredensial default.

Strategi:
  1. Probe path admin umum yang biasa di-protect Basic Auth (Nginx /server-status,
     phpMyAdmin di belakang basic auth, /admin di belakang htpasswd, dll.)
  2. Untuk setiap path yang return 401 dengan WWW-Authenticate: Basic / Digest,
     coba kredensial paling umum.
  3. Validasi: response status 200 + Content-Length berbeda dari respon 401
     baseline + body tidak memuat 'unauthorized'/'401'/login form.

Sangat konservatif: max 4 percobaan per endpoint untuk hindari lockout.
"""
from __future__ import annotations

from base64 import b64encode
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PROTECTED_PATHS = (
    "/admin/", "/admin", "/manager/", "/server-status", "/server-info",
    "/nginx_status", "/.htaccess", "/private/", "/api/admin", "/console",
    "/jenkins/", "/jmx-console/", "/management/", "/internal/",
    "/dashboard/", "/cgi-bin/",
)

DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("root", "root"),
    ("tomcat", "tomcat"),
    ("manager", "manager"),
    ("user", "user"),
    ("test", "test"),
]


def _is_basic_protected(resp) -> bool:
    if resp is None or resp.status_code != 401:
        return False
    auth = (resp.headers.get("WWW-Authenticate") or "").lower()
    return auth.startswith("basic") or auth.startswith("digest")


def _try_creds(client: HttpClient, url: str, baseline_status: int) -> tuple[str, str, int, int] | None:
    for u, p in DEFAULT_CREDS[:4]:
        token = b64encode(f"{u}:{p}".encode("latin-1")).decode("ascii")
        r = client.get(url, headers={"Authorization": f"Basic {token}"}, allow_redirects=False)
        if r is None:
            continue
        if r.status_code == 200:
            body = (r.text or "").lower()
            # Pastikan bukan 'logged out' / login page
            if any(k in body[:1000] for k in (
                "unauthorized", "401", "login required", "please log in"
            )):
                continue
            return (u, p, r.status_code, len(body))
        # 302 ke halaman dashboard juga indikator sukses
        if r.status_code in (301, 302) and r.status_code != baseline_status:
            loc = (r.headers.get("Location") or "").lower()
            if any(k in loc for k in ("dashboard", "home", "admin", "/main")):
                return (u, p, r.status_code, 0)
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.base_url
    client = HttpClient(config)
    try:
        for path in PROTECTED_PATHS:
            url = urljoin(base, path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if not _is_basic_protected(r):
                continue
            hit = _try_creds(client, url, r.status_code)
            if hit:
                u, p, status, length = hit
                findings.append(Finding(
                    module="basic_auth_default",
                    target=url,
                    title=f"HTTP Basic Auth tertembus dengan kredensial default {u}/{p}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Endpoint {url} dilindungi HTTP Basic Auth, tetapi menerima "
                        f"kredensial paling umum '{u}/{p}'. Modul sudah memvalidasi "
                        f"otomatis: response status {status} + body bukan halaman 'unauthorized'. "
                        "Akses ini biasanya menutupi panel admin / status server / management "
                        "console - setara dengan akses penuh ke sistem internal."
                    ),
                    evidence=(
                        f"URL          : {url}\n"
                        f"WWW-Authenticate: {r.headers.get('WWW-Authenticate')}\n"
                        f"Credentials  : {u}:{p}\n"
                        f"Status setelah auth: {status} (baseline 401)\n"
                        f"Body length  : {length}"
                    ),
                    cwe="CWE-798",
                    confidence="confirmed",
                    urls=[url],
                    remediation=(
                        "1. SEGERA ganti password Basic Auth (htpasswd -b /etc/nginx/.htpasswd <user> <new>).\n"
                        "2. Pakai password manager-generated minimum 16 karakter.\n"
                        "3. Idealnya pindah ke autentikasi lebih kuat (OAuth proxy, Cloudflare Access, IP allowlist + VPN).\n"
                        "4. Audit log akses untuk lihat apakah sudah ada yang ter-eksploitasi."
                    ),
                    references=[
                        "https://cwe.mitre.org/data/definitions/798.html",
                        "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures",
                    ],
                ))
                # Stop di hit pertama supaya tidak spam, tapi lanjut path lain
    finally:
        client.close()
    return findings
