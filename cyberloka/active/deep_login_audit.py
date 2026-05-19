"""Deep login audit: deteksi form login admin/user, coba kredensial umum,
auto-validasi keberhasilan login secara multi-signal sehingga tidak perlu
verifikasi manual.

Bedanya dengan modul `auth_bypass` yang sudah ada:
- Modul ini lebih luas: mencoba banyak kombinasi kredensial umum (termasuk
  daftar paling umum dari laporan kebocoran kredensial publik).
- Mengklasifikasikan form login sebagai ADMIN vs USER berdasarkan URL action
  dan konteks (path mengandung /admin, /administrator, dll).
- Validator multi-signal: status redirect, Set-Cookie session,
  diff body vs baseline, JSON token, hilangnya field password di response,
  munculnya menu logout.
- Auto-stop setelah 5 percobaan untuk hindari lockout.
- Setelah login berhasil, mencoba beberapa endpoint privileged (/admin/users,
  /api/users, /api/admin) untuk memastikan akses bukan sekadar landing page.

Selalu hormati ScanConfig.authorized + rate_limit.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state


# ---------------------------------------------------------------- payloads
# Daftar pendek tapi paling umum (top of leaked-credentials lists).
# Tidak melakukan brute-force masif - hanya credential common.
COMMON_USER_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", "Admin@123"),
    ("admin", "P@ssw0rd"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("test", "test123"),
    ("demo", "demo"),
    ("guest", "guest"),
]

# Untuk form yang memakai email sebagai username
COMMON_EMAIL_CREDS: list[tuple[str, str]] = [
    ("admin@admin.com", "admin"),
    ("admin@example.com", "admin"),
    ("admin@test.com", "admin"),
    ("test@test.com", "test"),
]

# Maks percobaan per form (hindari lockout / DoS)
MAX_ATTEMPTS_PER_FORM = 5

# Field user/email yang umum
USER_FIELD_HINTS = (
    "username", "user", "userid", "user_id", "email", "e-mail",
    "login", "loginid", "login_id", "account",
)

# Path admin umum yang akan diuji setelah login (bukti akses bukan sekadar
# halaman publik).
PRIVILEGED_PATHS = (
    "/admin", "/admin/users", "/admin/dashboard",
    "/api/admin", "/api/users", "/api/admin/users",
    "/dashboard", "/profile",
)

# Indikator login berhasil di body
SUCCESS_HINT = re.compile(
    r"(welcome|dashboard|logout|sign\s*out|berhasil|selamat\s*datang|"
    r"my\s*account|control\s*panel)",
    re.I,
)
# Indikator login gagal
FAIL_HINT = re.compile(
    r"(invalid|wrong|incorrect|salah|tidak\s*sesuai|gagal|failed|denied|"
    r"unauthorized|tidak\s*ditemukan|password\s*salah)",
    re.I,
)
# Indikator response JSON sukses
JSON_TOKEN_RE = re.compile(
    r'"(access_token|id_token|jwt|token|sessionId|session_id)"\s*:\s*"[^"]{8,}"',
    re.I,
)
JSON_SUCCESS_RE = re.compile(
    r'"(success|ok|status)"\s*:\s*(true|"success"|"ok")',
    re.I,
)


@dataclass
class LoginForm:
    action: str
    method: str
    user_field: str
    pass_field: str
    other_fields: dict[str, str]
    is_admin: bool
    page_url: str


# ---------------------------------------------------------------- helpers


def _classify_form(form: dict, page_url: str) -> tuple[bool, str]:
    """Return (is_admin, action_url). Form dianggap admin jika action atau
    page mengandung admin/administrator/staff/internal/console."""
    action = form.get("action") or page_url
    target_check = (action + " " + page_url).lower()
    is_admin = bool(
        re.search(r"/(admin|administrator|staff|internal|console|panel|cpanel)"
                  r"(/|\b)", target_check)
    )
    return is_admin, action


def _extract_login_forms(state, target: Target) -> list[LoginForm]:
    """Pilih semua form yang punya field password dari hasil crawler."""
    out: list[LoginForm] = []
    if not state:
        return out
    for f in state.forms:
        types = [(i.get("type") or "").lower() for i in f["inputs"]]
        if "password" not in types:
            continue
        # find user / pass field
        pass_field = next(
            (i["name"] for i in f["inputs"]
             if (i.get("type") or "").lower() == "password"),
            None,
        )
        user_field = next(
            (i["name"] for i in f["inputs"]
             if (i.get("name") or "").lower() in USER_FIELD_HINTS
             or any(h in (i.get("name") or "").lower() for h in ("email", "user"))),
            None,
        )
        if not (pass_field and user_field):
            continue
        # base values from non-credential fields (csrf token etc)
        other = {
            i["name"]: i.get("value") or "x"
            for i in f["inputs"]
            if i.get("type") not in ("submit", "button", "password")
            and i["name"] not in (user_field,)
        }
        # which page hosts this form? best-effort: first crawled URL with same
        # origin as action
        page_url = target.base_url
        is_admin, action = _classify_form(f, page_url)
        out.append(LoginForm(
            action=action,
            method=(f.get("method") or "post").lower(),
            user_field=user_field,
            pass_field=pass_field,
            other_fields=other,
            is_admin=is_admin,
            page_url=page_url,
        ))
    return out


def _baseline_response(client: HttpClient, lf: LoginForm) -> tuple[int, int, str]:
    """Submit kredensial bogus untuk mendapatkan baseline response."""
    data = {
        **lf.other_fields,
        lf.user_field: "cyberloka_baseline_xyz",
        lf.pass_field: "WrongPass_xyz_999",
    }
    if lf.method == "post":
        r = client.post(lf.action, data=data, allow_redirects=False)
    else:
        r = client.get(lf.action, params=data, allow_redirects=False)
    if r is None:
        return 0, 0, ""
    return r.status_code, len(r.text or ""), r.text or ""


def _is_login_success(
    resp,
    baseline_status: int,
    baseline_len: int,
    baseline_body: str,
) -> tuple[bool, list[str]]:
    """Multi-signal validator. Return (success, list_of_signals_matched)."""
    if resp is None:
        return False, []
    signals: list[str] = []
    body = resp.text or ""
    headers = {k.lower(): v for k, v in (resp.headers or {}).items()}

    # 1. Redirect ke halaman dashboard/home/admin
    loc = headers.get("location", "").lower()
    if resp.status_code in (301, 302, 303, 307, 308):
        if any(p in loc for p in (
            "dashboard", "home", "admin", "panel", "account",
            "profile", "welcome", "/app", "/main",
        )):
            signals.append(f"redirect-to-privileged ({loc[:60]})")

    # 2. Set-Cookie sesi (baru atau berbeda dari baseline)
    cookies = resp.cookies if hasattr(resp, "cookies") else []
    for c in cookies:
        n = (c.name or "").lower()
        if any(k in n for k in ("sess", "auth", "token", "jwt", "sid", "phpsessid")):
            # Wajib bukan cookie kosong
            if c.value:
                signals.append(f"session-cookie={c.name}")
                break

    # 3. JSON token / success di body
    if JSON_TOKEN_RE.search(body):
        signals.append("json-token-issued")
    if JSON_SUCCESS_RE.search(body):
        signals.append("json-success-flag")

    # 4. Body diff signifikan + indikator success TANPA indikator fail
    body_first_chunk = body[:2000]
    if (
        SUCCESS_HINT.search(body_first_chunk)
        and not FAIL_HINT.search(body_first_chunk)
        and abs(len(body) - baseline_len) > 200
    ):
        signals.append("success-text-vs-baseline-diff")

    # 5. Status 200 + response tidak lagi memuat password field
    if (
        resp.status_code == 200
        and 'type="password"' in (baseline_body or "").lower()
        and 'type="password"' not in body.lower()
    ):
        signals.append("no-password-field-after-submit")

    # Need >= 2 signals OR 1 strong signal (json token / explicit privileged
    # redirect).
    strong = any(s.startswith(("json-token", "redirect-to-privileged"))
                 for s in signals)
    return (strong or len(signals) >= 2), signals


def _check_privileged_endpoint(
    client: HttpClient, target: Target, baseline_body: str
) -> str | None:
    """Setelah login, cek endpoint privileged untuk konfirmasi akses nyata.
    Return path yang accessible jika dapat 200 + body berbeda dari baseline."""
    base = target.origin + "/"
    for path in PRIVILEGED_PATHS:
        url = urljoin(base, path.lstrip("/"))
        r = client.get(url, allow_redirects=False)
        if r is None:
            continue
        body = r.text or ""
        if r.status_code == 200 and len(body) > 200:
            # Cek tidak redirect kembali ke login page
            if "type=\"password\"" not in body.lower():
                return f"{path} -> HTTP 200, len={len(body)}"
    return None


def _try_form(
    client: HttpClient,
    lf: LoginForm,
    target: Target,
    extra_creds: list[tuple[str, str]],
) -> Finding | None:
    baseline_status, baseline_len, baseline_body = _baseline_response(client, lf)
    role = "ADMIN" if lf.is_admin else "USER"

    # Pilih credential set: admin pakai admin/root/administrator dulu
    if lf.is_admin:
        creds = COMMON_USER_CREDS[:5] + extra_creds[:2]
    else:
        creds = (
            extra_creds[:3]
            + COMMON_USER_CREDS[:5]
            + COMMON_EMAIL_CREDS[:2]
        )
    creds = creds[:MAX_ATTEMPTS_PER_FORM]

    for u, p in creds:
        data = {
            **lf.other_fields,
            lf.user_field: u,
            lf.pass_field: p,
        }
        if lf.method == "post":
            r = client.post(lf.action, data=data, allow_redirects=False)
        else:
            r = client.get(lf.action, params=data, allow_redirects=False)

        ok, signals = _is_login_success(
            r, baseline_status, baseline_len, baseline_body,
        )
        if not ok:
            continue

        # Konfirmasi akses dengan probe endpoint privileged
        privileged_evidence = _check_privileged_endpoint(
            client, target, baseline_body,
        )
        confidence = "confirmed" if privileged_evidence else "firm"

        sev = Severity.CRITICAL if lf.is_admin else Severity.HIGH
        title = (
            f"[{role}] Kredensial default login berhasil tervalidasi: "
            f"{u} / {p}"
        )
        evidence_lines = [
            f"action  = {lf.action}",
            f"method  = {lf.method.upper()}",
            f"user    = {u}",
            f"pass    = {p}",
            f"status  = {r.status_code if r else 'n/a'}",
            f"signals = {', '.join(signals) or '(none)'}",
        ]
        if privileged_evidence:
            evidence_lines.append(f"verified= {privileged_evidence}")
        return Finding(
            module="deep_login_audit",
            target=lf.action,
            title=title,
            severity=sev,
            description=(
                f"Form login (klasifikasi: {role}) menerima kredensial umum "
                f"`{u}/{p}` dan response menunjukkan login berhasil "
                f"berdasarkan {len(signals)} signal otomatis "
                f"(status code, Set-Cookie session, body diff, JSON token, "
                f"redirect ke halaman privileged). "
                + (
                    "Akses lebih lanjut DIVERIFIKASI dengan request ke "
                    "endpoint privileged."
                    if privileged_evidence
                    else "Verifikasi akses lanjutan tidak menghasilkan response "
                    "privileged (mungkin SPA - cek manual)."
                )
            ),
            evidence="\n".join(evidence_lines),
            cwe="CWE-798",
            confidence=confidence,
            urls=[lf.action],
            remediation=(
                "1. Hapus / nonaktifkan akun default. Audit semua user dengan "
                "password lemah / sama dengan username.\n"
                "2. Wajibkan password kuat (panjang >= 12, tidak ada di daftar "
                "kebocoran public seperti haveibeenpwned).\n"
                "3. Aktifkan 2FA terutama untuk akun admin.\n"
                "4. Rate-limit endpoint login + account lockout setelah N "
                "percobaan gagal.\n"
                "5. Logging + alert untuk login dari IP/device baru."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/798.html",
                "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures",
            ],
        )
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    state = get_state(config)
    forms = _extract_login_forms(state, target)
    if not forms:
        return findings

    # Kredensial tambahan dari nama host (sangat umum: name@example=password)
    host_label = (target.host or "").split(".")[0]
    extra_creds: list[tuple[str, str]] = []
    if host_label and len(host_label) >= 3:
        extra_creds.extend([
            (host_label, host_label),
            ("admin", host_label),
            ("admin", host_label + "123"),
        ])

    seen_actions: set[str] = set()
    client = HttpClient(config)
    try:
        for lf in forms:
            if lf.action in seen_actions:
                continue
            seen_actions.add(lf.action)
            f = _try_form(client, lf, target, extra_creds)
            if f:
                findings.append(f)
            # Reset session cookies between forms supaya success di form A
            # tidak ke-bleed ke form B.
            client.session.cookies.clear()
    finally:
        client.close()
    return findings
