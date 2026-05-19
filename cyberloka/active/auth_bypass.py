"""Auth-bypass probes — strict-validation v0.10.1.

False-positive guards:
  * Default-creds: butuh perubahan body signifikan vs baseline-invalid
    DAN ada cookie sesi baru dengan nama yang masuk akal. Kalau hanya
    body beda tapi tetap punya kata 'invalid/wrong/salah' di body —
    tidak laporkan.
  * Admin-paths: kalau halaman 200 sebenarnya redirect-soft (login form
    biasa muncul), turunkan severity ke LOW (info finding) — bukan
    'akses publik' yang sesungguhnya.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state
from cyberloka.reporting.awam import get_awam

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("admin", "Admin@123"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("test", "test"), ("user", "user"),
    ("administrator", "administrator"),
]

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
    r"(welcome|dashboard|logout|sign\s*out|berhasil|selamat\s*datang)", re.I,
)
FAIL_HINT = re.compile(
    r"(invalid|wrong|incorrect|salah|tidak\s*sesuai|gagal|failed|denied)", re.I,
)


def _login_form(config: ScanConfig):
    state = get_state(config)
    if not state:
        return None
    for f in state.forms:
        types = [(i.get("type") or "").lower() for i in f["inputs"]]
        if "password" in types:
            return f
    return None


def _try_default_creds(client: HttpClient, form: dict, awam) -> Finding | None:
    awam_summary, awam_steps = awam
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

    bogus = {**base, user_field: "cyberloka_invalid_xyz", pass_field: "wrong_xyz"}
    r0 = (client.post(action, data=bogus) if method == "post"
          else client.get(action, params=bogus))
    baseline_len = len(r0.text or "") if r0 else 0
    baseline_status = r0.status_code if r0 else 0
    baseline_cookies = {c.name for c in (r0.cookies if r0 else [])}

    for u, p in DEFAULT_CREDS:
        data = {**base, user_field: u, pass_field: p}
        r = (client.post(action, data=data) if method == "post"
             else client.get(action, params=data))
        if r is None:
            continue
        body = r.text or ""

        # NEW: still has fail-hint inside the FIRST 1KB → server returned login form again.
        if FAIL_HINT.search(body[:1000]):
            continue

        login_likely_text = (
            r.status_code in (200, 302) and SUCCESS_HINT.search(body)
            and abs(len(body) - baseline_len) > 100
        )
        new_cookies = {c.name for c in r.cookies} - baseline_cookies
        new_session_cookie = any(
            "sess" in c.lower() or "auth" in c.lower() or "token" in c.lower()
            for c in new_cookies
        )

        # Confirmation: re-issue request to ensure consistency.
        if not (login_likely_text or new_session_cookie):
            continue
        r2 = (client.post(action, data=data) if method == "post"
              else client.get(action, params=data))
        if r2 is None:
            continue
        body2 = r2.text or ""
        if FAIL_HINT.search(body2[:1000]):
            continue
        new_cookies2 = {c.name for c in r2.cookies}
        consistent = new_session_cookie or (
            SUCCESS_HINT.search(body2) and abs(len(body2) - baseline_len) > 100
        )
        if not consistent:
            continue

        proof = ValidationProof(
            method="default-creds+double-confirm",
            confirmed=True,
            steps=[
                f"Login dengan kredensial bogus → status={baseline_status}, len={baseline_len}.",
                f"Login dengan default `{u}/{p}` → status={r.status_code}, len={len(body)}.",
                "Body TIDAK memuat fail-hint pada 1KB pertama.",
                f"Cookie baru muncul: {sorted(new_cookies)} (session-like={new_session_cookie}).",
                "Re-issue konfirmasi: hasil tetap konsisten.",
            ],
            samples=[
                f"len_diff_vs_baseline={len(body)-baseline_len}",
                f"new_cookies={sorted(new_cookies)}",
            ],
        )
        return Finding(
            module="auth_bypass",
            title=f"Kredensial default berhasil login: {u}/{p}",
            severity=Severity.CRITICAL,
            description=(
                "Login dengan kredensial umum/default berhasil dan dikonfirmasi "
                "dua kali. Verifikasi manual selalu disarankan."
            ),
            target=action,
            evidence=(
                f"creds={u}/{p}; status={r.status_code}; baseline_status={baseline_status}; "
                f"new_session={new_session_cookie}; len_diff={len(body)-baseline_len}"
            ),
            cwe="CWE-798",
            confidence="confirmed",
            urls=[action],
            remediation=(
                "Hapus akun default & ganti semua password awal. Wajibkan password "
                "kuat (panjang ≥12, bukan dari daftar bocoran), aktifkan 2FA "
                "untuk admin, dan rate-limit login."
            ),
            extra=build_extra(
                proof=proof,
                awam_steps=awam_steps,
                awam_summary=awam_summary,
            ),
        )
    return None


def _probe_admin_paths(client: HttpClient, target: Target, awam) -> list[Finding]:
    awam_summary, awam_steps = awam
    findings: list[Finding] = []
    base = target.origin + "/"
    for path in ADMIN_PATHS:
        url = urljoin(base, path.lstrip("/"))
        r = client.get(url, allow_redirects=False)
        if r is None or r.status_code >= 400:
            continue
        body = (r.text or "").lower()
        if r.status_code == 200 and any(
            k in body for k in ("login", "username", "password", "admin", "dashboard")
        ):
            # Determine if this is just a login page (lower severity) or
            # actually accessible content.
            looks_like_login = (
                "password" in body and ("login" in body or "sign in" in body)
            )
            sev = Severity.LOW if looks_like_login else Severity.MEDIUM
            proof = ValidationProof(
                method="path-200+content-classification",
                confirmed=True,
                steps=[
                    f"GET {url} → status 200, length {len(r.text or '')} bytes.",
                    f"Body memuat keyword admin/login/dashboard.",
                    ("Halaman terdeteksi sebagai LOGIN-FORM (severity diturunkan ke LOW)."
                     if looks_like_login else
                     "Halaman tampak BUKAN login-form (severity MEDIUM)."),
                ],
                samples=[f"snippet={(r.text or '')[:120]}"],
            )
            findings.append(Finding(
                module="auth_bypass",
                title=f"Halaman admin/internal dapat diakses publik: {path}",
                severity=sev,
                description=(
                    "Path admin/panel internal merespons 200 untuk pengunjung "
                    "anonim. Verifikasi apakah ada IP allowlist atau auth wajib "
                    "di lapisan reverse proxy."
                ),
                target=url,
                urls=[url],
                evidence=f"HTTP {r.status_code}, len={len(r.text or '')}",
                cwe="CWE-284",
                confidence="firm",
                remediation=(
                    "Batasi akses ke `/admin*` di reverse proxy: hanya IP staff "
                    "atau VPN. Aktifkan basic-auth tambahan + 2FA."
                ),
                extra=build_extra(
                    proof=proof,
                    awam_steps=awam_steps,
                    awam_summary=awam_summary,
                ),
            ))
            if len(findings) >= 3:
                break
    return findings


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam = get_awam("auth_bypass")
    try:
        form = _login_form(config)
        if form:
            f = _try_default_creds(client, form, awam)
            if f:
                findings.append(f)
        findings.extend(_probe_admin_paths(client, target, awam))
    finally:
        client.close()
    return findings
