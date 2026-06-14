"""Authentication bypass attempts: default creds + admin paths + auth token replay."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state
from cyberloka.core import probe

# Common default credential pairs (small list — kami tidak brute-force)
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("admin", "Admin@123"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("test", "test"), ("user", "user"),
    ("administrator", "administrator"),
]

# Common admin/internal paths that should not be public
ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/admin/login", "/admin/index.php", "/admin/dashboard",
    "/panel", "/cpanel", "/controlpanel",
    "/manager", "/manage",
    "/dashboard", "/dash",
    "/internal", "/internal/", "/staff", "/staff/",
    "/console", "/control",
]

LOGIN_FIELDS_USER = ("username", "email", "user", "userid", "login")
SUCCESS_HINT = re.compile(
    r"(welcome|dashboard|logout|sign\s*out|berhasil|selamat\s*datang)",
    re.I,
)
FAIL_HINT = re.compile(
    r"(invalid|wrong|incorrect|salah|tidak\s*sesuai|gagal|failed|denied)",
    re.I,
)


def _login_form(config: ScanConfig) -> dict | None:
    state = get_state(config)
    if not state:
        return None
    for f in state.forms:
        types = [(i.get("type") or "").lower() for i in f["inputs"]]
        if "password" in types:
            return f
    return None


def _try_default_creds(client: HttpClient, form: dict) -> Finding | None:
    user_field = next(
        (i["name"] for i in form["inputs"]
         if (i.get("name") or "").lower() in LOGIN_FIELDS_USER
         or "email" in (i.get("name") or "").lower()),
        None,
    )
    pass_field = next(
        (i["name"] for i in form["inputs"]
         if (i.get("type") or "").lower() == "password"),
        None,
    )
    if not (user_field and pass_field):
        return None

    base = {
        i["name"]: i.get("value") or "x"
        for i in form["inputs"]
        if i.get("type") not in ("submit", "button")
    }
    method = (form.get("method") or "post").lower()
    action = form.get("action", "")

    # Establish baseline with random invalid creds
    bogus = {**base, user_field: "cyberloka_invalid_xyz", pass_field: "wrong_xyz"}
    r0 = (client.post(action, data=bogus) if method == "post"
          else client.get(action, params=bogus))
    baseline_len = len(r0.text or "") if r0 else 0
    baseline_status = r0.status_code if r0 else 0
    # Cookie yang SUDAH di-set walau login gagal (CSRF/session kosong) bukan bukti
    # login berhasil — catat agar tidak dihitung sebagai "sesi baru".
    baseline_cookies = {c.name.lower() for c in (r0.cookies if r0 else [])}


    for u, p in DEFAULT_CREDS:
        data = {**base, user_field: u, pass_field: p}
        r = (client.post(action, data=data) if method == "post"
             else client.get(action, params=data))
        if r is None:
            continue
        body = r.text or ""
        # Heuristic: status 200/302 + significantly different from baseline +
        # mengandung indikator success.
        login_likely = (
            r.status_code in (200, 302) and
            (SUCCESS_HINT.search(body) and not FAIL_HINT.search(body[:500]))
            and abs(len(body) - baseline_len) > 100
        )
        # Cookie sesi BARU (tidak ada saat login gagal) = sinyal pendukung, bukan
        # pemicu tunggal — mencegah false positive di situs yang selalu set cookie.
        new_session_cookie = any(
            ("sess" in c.name.lower() or "auth" in c.name.lower() or "token" in c.name.lower())
            and c.name.lower() not in baseline_cookies
            for c in r.cookies
        )
        if login_likely:
            return Finding(
                module="auth_bypass",
                title=f"Kredensial default berhasil login: {u}/{p}",
                severity=Severity.CRITICAL,
                description=(
                    "Login dengan kredensial umum/default tampak berhasil. "
                    "Verifikasi manual diperlukan, tapi ini adalah salah satu "
                    "celah paling klasik dan berbahaya."
                ),
                target=action,
                evidence=(
                    f"creds={u}/{p}; status={r.status_code}; "
                    f"baseline_status={baseline_status}; new_session={new_session_cookie}; "
                    f"len_diff={len(body)-baseline_len}"
                ),
                cwe="CWE-798",
                confidence="tentative",
                remediation=(
                    "Hapus akun default & ganti semua password awal. Wajibkan password "
                    "kuat (panjang ≥12, bukan dari daftar bocoran), aktifkan 2FA "
                    "untuk admin, dan rate-limit login."
                ),
            )
    return None


def _probe_admin_paths(client: HttpClient, target: Target) -> list[Finding]:
    findings: list[Finding] = []
    base = target.origin + "/"
    # Penanda UI login/admin yang sesungguhnya (bukan kata "admin" generik di teks).
    def _looks_admin(ctype: str, body: str) -> bool:
        low = body.lower()
        return any(k in low for k in ("login", "sign in", "username", "type=\"password\"", "type='password'"))

    for path in ADMIN_PATHS:
        url = urljoin(base, path.lstrip("/"))
        # verify_real: harus 200, BUKAN catch-all/SPA fallback, DAN punya UI login/admin.
        r = probe.verify_real(client, target, url, validator=_looks_admin)
        if r is not None:
            findings.append(Finding(
                module="auth_bypass",
                title=f"Halaman admin/internal dapat diakses publik: {path}",
                severity=Severity.MEDIUM,
                description=(
                    "Path admin/panel internal merespons 200 untuk pengunjung "
                    "anonim. Verifikasi apakah ada IP allowlist atau auth wajib "
                    "di lapisan reverse proxy."
                ),
                target=url,
                evidence=f"HTTP {r.status_code}, len={len(r.text or '')}",
                cwe="CWE-284",
                remediation=(
                    "Batasi akses ke `/admin*` di reverse proxy: hanya IP staff "
                    "atau VPN. Aktifkan basic-auth tambahan + 2FA."
                ),
            ))
            if len(findings) >= 3:
                break
    return findings


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        form = _login_form(config)
        if form:
            f = _try_default_creds(client, form)
            if f:
                findings.append(f)
        findings.extend(_probe_admin_paths(client, target))
    finally:
        client.close()
    return findings
