"""Auth-bypass probes — strict-validation v0.10.1.

False-positive guards:
  * Default-creds: butuh perubahan body signifikan vs baseline-invalid
    DAN ada cookie sesi baru dengan nama yang masuk akal. Kalau hanya
    body beda tapi tetap punya kata 'invalid/wrong/salah' di body —
    tidak laporkan.
  * Admin-paths (v0.10.6 — perbaikan false-positive soft-404/SPA):
    Versi lama melaporkan path admin hanya dari `HTTP 200` + body memuat
    substring generik (`admin`/`login`/`dashboard`). Situs SPA (Next.js/Nuxt)
    membalas 200 berisi BERANDA atau halaman "404" yang dirender klien untuk
    path APA PUN, dan beranda itu biasanya memuat kata "admin"/"login" →
    `/administrator` dilaporkan padahal sebenarnya 404 saat di-cek manual.
    Sekarang admin-path WAJIB lolos:
      1. Soft-404 guard: response TIDAK identik dengan path random (control).
      2. Homepage guard: response TIDAK identik dengan beranda `/`.
      3. Not-found guard: body tidak memuat marker "404 / not found /
         halaman tidak ditemukan".
      4. Genuine-signal: ada FORM password sungguhan, atau signature software
         admin yang dikenal, atau <title> admin/login (dan bukan shell SPA).
    Mere substring "admin" pada shell SPA generik TIDAK lagi cukup.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
    looks_like_html_shell,
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

# --- Admin-path validation helpers (v0.10.6) -------------------------------
# Marker "halaman tidak ada" yang dirender klien di dalam response 200 (soft-404).
NOTFOUND_MARKERS = re.compile(
    r"(?:\b404\b|not\s*found|page\s*not\s*found|halaman\s*(?:tidak\s*ditemukan|"
    r"tidak\s*ada)|tidak\s*ditemukan|error\s*404|this\s*page\s*could\s*not)",
    re.I,
)
# FORM login sungguhan: input bertipe password.
PASSWORD_INPUT = re.compile(r"<input[^>]+type\s*=\s*[\"']?password", re.I)
# <title> yang spesifik halaman admin/login (bukan beranda generik).
ADMIN_TITLE = re.compile(
    r"<title>[^<]*\b(admin|administrator|login|log\s*in|sign\s*in|dashboard|"
    r"panel|cpanel|control\s*panel|masuk)\b",
    re.I,
)
# Marker bahwa kita sudah BERADA di dalam panel (akses tanpa auth) — bukan form login.
INSIDE_PANEL = re.compile(
    r"(logout|sign\s*out|keluar|<nav[^>]*admin|admin[-_ ]?menu|"
    r"data-?table|stat[-_ ]?card|widget)",
    re.I,
)
# Signature software admin yang dikenal.
ADMIN_SOFTWARE = re.compile(
    r"(wp-login|wp-admin|/administrator/index\.php|com_login|joomla|"
    r"phpmyadmin|pma_|grafana|kibana|django administration|csrfmiddlewaretoken|"
    r"adminlte|coreui|laravel|x-powered-by:\s*express|plesk|cpanel)",
    re.I,
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


def _sig(resp) -> tuple[int, str] | None:
    """Tanda-tangan ringan (len, 200 char awal) untuk response 200 ber-isi."""
    if resp is None or resp.status_code != 200 or not resp.content:
        return None
    body = resp.text or ""
    return (len(body), body[:200])


def _same_as(body: str, sig: tuple[int, str] | None) -> bool:
    """True bila body pada dasarnya identik dengan signature (catch-all/echo)."""
    if not sig:
        return False
    ln, head = sig
    return abs(len(body) - ln) <= 64 and body[:200] == head


def _probe_admin_paths(client: HttpClient, target: Target, awam) -> list[Finding]:
    awam_summary, awam_steps = awam
    findings: list[Finding] = []
    base = target.origin + "/"

    # --- Baseline kontrol: path random pasti-tak-ada + beranda situs. -------
    rand = f"cyberloka_{secrets.token_hex(6)}_noexist"
    ctrl_sig = _sig(client.get(urljoin(base, rand), allow_redirects=False))
    root_sig = _sig(client.get(base, allow_redirects=False))

    for path in ADMIN_PATHS:
        url = urljoin(base, path.lstrip("/"))
        r = client.get(url, allow_redirects=False)
        # Hanya 200 dengan isi yang relevan; 3xx (redirect ke login) & 4xx/5xx
        # berarti TIDAK dapat diakses publik → bukan temuan.
        if r is None or r.status_code != 200 or not r.content:
            continue
        body = r.text or ""
        low = body.lower()

        # 1) Soft-404 / catch-all: identik dengan path random → server balas
        #    hal yang sama untuk path apa pun. BUKAN halaman admin nyata.
        if _same_as(body, ctrl_sig):
            continue
        # 2) Echo beranda: server menyajikan beranda untuk path ini.
        if _same_as(body, root_sig):
            continue
        # 3) Client-side 404 di dalam response 200 (kasus simkopdes:
        #    /administrator "200" tapi isinya halaman "404 not found").
        if NOTFOUND_MARKERS.search(body[:3000]):
            continue

        # --- Sinyal admin/login yang SUNGGUHAN & spesifik halaman ini. ------
        has_pw_form = bool(PASSWORD_INPUT.search(body))
        has_software = bool(ADMIN_SOFTWARE.search(body))
        has_admin_title = bool(ADMIN_TITLE.search(body))
        inside_panel = bool(INSIDE_PANEL.search(body)) and not has_pw_form
        is_shell = looks_like_html_shell(body)

        # Substring "admin" pada shell SPA generik TIDAK cukup. Wajib salah satu:
        #   - form password sungguhan, ATAU
        #   - signature software admin yang dikenal, ATAU
        #   - <title> admin/login DAN bukan shell SPA generik.
        genuine = has_pw_form or has_software or (has_admin_title and not is_shell)
        if not genuine:
            continue

        # Klasifikasi severity & confidence.
        if inside_panel and not has_pw_form:
            # Konten panel terlihat tanpa diminta login → akses publik nyata.
            sev = Severity.HIGH
            confidence = "confirmed"
            kind = "KONTEN PANEL terlihat tanpa autentikasi (akses publik nyata)"
        elif has_pw_form:
            # Halaman login admin yang dapat dijangkau — informational.
            sev = Severity.LOW
            confidence = "firm"
            kind = "FORM LOGIN admin dapat dijangkau (endpoint terkonfirmasi ada)"
        else:
            sev = Severity.MEDIUM
            confidence = "firm"
            kind = "Halaman admin terindikasi (software/title admin terdeteksi)"

        # Double-confirm: ulangi sekali, pastikan konsisten & bukan flukes.
        r2 = client.get(url, allow_redirects=False)
        body2 = (r2.text or "") if r2 is not None else ""
        if (r2 is None or r2.status_code != 200
                or NOTFOUND_MARKERS.search(body2[:3000])
                or _same_as(body2, ctrl_sig) or _same_as(body2, root_sig)):
            continue

        proof = ValidationProof(
            method="admin-path: soft404-reject+control-diff+genuine-signal+double-confirm",
            confirmed=(confidence == "confirmed"),
            steps=[
                f"GET {url} → 200, len={len(body)}.",
                ("Berbeda dari path random kontrol (bukan catch-all 200)."
                 if ctrl_sig else "Path random kontrol tidak balas 200 (baik)."),
                ("Berbeda dari beranda `/` (bukan echo beranda)."
                 if root_sig else "Beranda tidak balas 200 untuk dibandingkan."),
                "Body TIDAK memuat marker 404/not-found.",
                f"Sinyal admin sungguhan: pw_form={has_pw_form}, "
                f"software={has_software}, admin_title={has_admin_title}, "
                f"inside_panel={inside_panel}, spa_shell={is_shell}.",
                "Double-confirm: request ke-2 tetap konsisten.",
                f"Klasifikasi: {kind}.",
            ],
            samples=[f"snippet={body[:160]!r}"],
            notes=f"severity={sev.value}; {kind}",
        )
        findings.append(Finding(
            module="auth_bypass",
            title=f"Halaman admin/internal dapat diakses publik: {path}",
            severity=sev,
            description=(
                f"Path admin/panel internal merespons 200 untuk pengunjung anonim "
                f"dan tervalidasi sebagai halaman admin asli ({kind}) — bukan "
                f"soft-404/echo beranda SPA. Verifikasi apakah ada IP allowlist "
                f"atau auth wajib di lapisan reverse proxy."
            ),
            target=url,
            urls=[url],
            evidence=f"HTTP {r.status_code}, len={len(body)}, kind={kind}",
            cwe="CWE-284",
            confidence=confidence,
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
