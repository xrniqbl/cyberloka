"""Session & login posture checks.

Pengecekan aman (tidak melakukan brute force):

- Login form di-serve via HTTP (bukan HTTPS).
- Cookie sesi tanpa Secure / HttpOnly / SameSite.
- Session fixation: cookie sesi diberikan sebelum login dan tidak berubah
  setelah login gagal/berhasil.
- Account enumeration: pesan/timing berbeda saat user valid vs invalid.
- Session ID pendek/predictable (panjang token < 16, base16, sequential).
"""
from __future__ import annotations

import re
import secrets
import string
import time

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

LOGIN_HINTS = re.compile(r"login|signin|masuk|sign-in|auth", re.I)
USER_FIELDS = ("username", "email", "user", "login", "userid", "username_email")
PASS_FIELDS = ("password", "passwd", "pwd", "passphrase", "pass")

INVALID_USER_MARKERS = (
    "user not found", "no such user", "akun tidak ditemukan",
    "username tidak terdaftar", "email not registered",
    "tidak terdaftar",
)
INVALID_PASS_MARKERS = (
    "password salah", "wrong password", "incorrect password",
    "kata sandi salah", "password yang anda masukkan salah",
)


def _login_forms(config: ScanConfig) -> list[dict]:
    state = get_state(config)
    if not state:
        return []
    out: list[dict] = []
    for form in state.forms:
        names = [(i.get("name") or "").lower() for i in form["inputs"]]
        types = [(i.get("type") or "").lower() for i in form["inputs"]]
        has_pass = any(t == "password" for t in types) or any(
            n in PASS_FIELDS for n in names
        )
        has_user = any(n in USER_FIELDS for n in names) or any("password" not in n and "email" in n for n in names)
        action_hint = LOGIN_HINTS.search(form.get("action") or "")
        if has_pass and (has_user or action_hint):
            out.append(form)
    return out


def _session_cookies(resp) -> list:
    if resp is None:
        return []
    out = []
    for c in resp.cookies:
        n = c.name.lower()
        if any(k in n for k in ("sess", "auth", "token", "phpsessid", "jsessionid")):
            out.append(c)
    return out


def _check_login_over_http(client: HttpClient, target: Target, forms: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    if target.scheme == "https":
        # Periksa form login: action ke http://?
        for form in forms:
            action = (form.get("action") or "").lower()
            if action.startswith("http://"):
                findings.append(
                    Finding(
                        module="session",
                        title="Form login mengirim kredensial via HTTP",
                        severity=Severity.HIGH,
                        description=(
                            "Form login pada halaman HTTPS mengarah ke endpoint HTTP. "
                            "Kredensial dapat disadap di jaringan."
                        ),
                        target=form.get("action", ""),
                        cwe="CWE-319",
                        remediation=(
                            "Kirim form login lewat HTTPS, redirect HTTP -> HTTPS, "
                            "aktifkan HSTS dengan `includeSubDomains; preload`."
                        ),
                    )
                )
    else:
        findings.append(
            Finding(
                module="session",
                title="Halaman login disajikan via HTTP",
                severity=Severity.HIGH,
                description="Login dilayani via HTTP, kredensial dapat disadap.",
                target=target.base_url,
                cwe="CWE-319",
                remediation="Paksa HTTPS, aktifkan HSTS, redirect 301 dari HTTP.",
            )
        )
    return findings


def _check_session_cookie_attrs(client: HttpClient, target: Target) -> list[Finding]:
    findings: list[Finding] = []
    resp = client.get(target.base_url)
    cookies = _session_cookies(resp)
    for c in cookies:
        rest = getattr(c, "_rest", {}) or {}
        flags = []
        if not c.secure:
            flags.append("Secure")
        # HttpOnly biasanya di _rest
        if not (rest.get("HttpOnly") or rest.get("httponly")):
            flags.append("HttpOnly")
        ss = (rest.get("SameSite") or rest.get("samesite") or "").lower()
        if not ss or ss == "none":
            flags.append(f"SameSite (saat ini={ss or 'missing'})")
        if flags:
            findings.append(
                Finding(
                    module="session",
                    title=f"Cookie sesi `{c.name}` kekurangan atribut: {', '.join(flags)}",
                    severity=Severity.HIGH if "Secure" in flags or "HttpOnly" in flags else Severity.MEDIUM,
                    description=(
                        "Cookie sesi tidak menggunakan atribut keamanan minimum, "
                        "membuka celah session hijack/CSRF."
                    ),
                    target=target.base_url,
                    evidence=f"cookie={c.name}; secure={c.secure}; rest={dict(rest)}",
                    cwe="CWE-614",
                    remediation=(
                        "Set `Secure; HttpOnly; SameSite=Lax` (atau Strict) pada cookie "
                        "sesi. Untuk SPA cross-site, gunakan SameSite=Strict + token "
                        "anti-CSRF."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                    ],
                )
            )
    return findings


def _check_session_id_quality(client: HttpClient, target: Target) -> list[Finding]:
    findings: list[Finding] = []
    resp = client.get(target.base_url)
    cookies = _session_cookies(resp)
    for c in cookies:
        v = c.value or ""
        if len(v) < 16:
            findings.append(
                Finding(
                    module="session",
                    title=f"Session ID terlalu pendek: `{c.name}` ({len(v)} char)",
                    severity=Severity.HIGH,
                    description=(
                        "Token sesi pendek mempermudah brute force / prediction. "
                        "Standar minimal 128-bit entropy (~22 char base64)."
                    ),
                    target=target.base_url,
                    evidence=f"length={len(v)}",
                    cwe="CWE-331",
                    remediation=(
                        "Gunakan generator session ID kriptografis dari framework "
                        "(mis. `secrets.token_urlsafe(32)` di Python)."
                    ),
                )
            )
        # Hampir-numeric / sequential
        if v.isdigit() or all(ch in string.hexdigits and len(v) <= 12 for ch in v):
            findings.append(
                Finding(
                    module="session",
                    title=f"Session ID terlihat predictable: `{c.name}`",
                    severity=Severity.HIGH,
                    description=(
                        "Token sesi terlihat numerik/hex pendek. Pola ini rentan "
                        "ditebak atau di-bruteforce paralel."
                    ),
                    target=target.base_url,
                    evidence=f"value-prefix={v[:16]}",
                    cwe="CWE-330",
                    remediation=(
                        "Gunakan random byte kriptografis untuk session ID, jangan "
                        "increment / hash predictable input."
                    ),
                )
            )
    return findings


def _check_session_fixation(client: HttpClient, forms: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for form in forms[:1]:  # cukup 1 form login untuk hint
        # 1. GET halaman login -> ambil cookie sesi
        action = form.get("action", "")
        r1 = client.get(action)
        pre_cookies = {c.name: c.value for c in (r1.cookies if r1 else [])}
        # 2. Submit kredensial bogus
        bogus = secrets.token_hex(8)
        data = {}
        for i in form["inputs"]:
            n = (i.get("name") or "").lower()
            if i.get("type") == "password" or n in PASS_FIELDS:
                data[i["name"]] = bogus
            elif n in USER_FIELDS or "email" in n:
                data[i["name"]] = f"cyberloka_{bogus}@example.com"
            elif i.get("type") not in ("submit", "button"):
                data[i["name"]] = i.get("value") or "x"
        if not data:
            continue
        method = (form.get("method") or "get").lower()
        r2 = (client.post(action, data=data) if method == "post"
              else client.get(action, params=data))
        post_cookies = {c.name: c.value for c in (r2.cookies if r2 else [])}
        # Jika ada cookie sesi lama yang tidak di-rotate, hint fixation
        sess_keys = [k for k in pre_cookies if any(
            tag in k.lower() for tag in ("sess", "auth", "phpsessid", "jsessionid")
        )]
        for k in sess_keys:
            if k in post_cookies and post_cookies[k] == pre_cookies[k]:
                findings.append(
                    Finding(
                        module="session",
                        title=f"Cookie sesi `{k}` tidak di-rotate setelah submit login",
                        severity=Severity.MEDIUM,
                        description=(
                            "Setelah submit form login, cookie sesi yang sama "
                            "tetap dipakai. Idealnya server menerbitkan ID baru pasca "
                            "autentikasi untuk mencegah session fixation."
                        ),
                        target=action,
                        evidence=f"cookie={k}; sama sebelum & sesudah login",
                        cwe="CWE-384",
                        confidence="tentative",
                        remediation=(
                            "Generate session ID baru setelah login berhasil "
                            "(`session.regenerate()` di PHP, "
                            "`request.session.cycle_key()` di Django)."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Session_fixation",
                        ],
                    )
                )
    return findings


def _check_account_enum(client: HttpClient, forms: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for form in forms[:1]:
        action = form.get("action", "")
        method = (form.get("method") or "get").lower()
        user_field = next(
            (i["name"] for i in form["inputs"]
             if (i.get("name") or "").lower() in USER_FIELDS or "email" in (i.get("name") or "").lower()),
            None,
        )
        pass_field = next(
            (i["name"] for i in form["inputs"]
             if (i.get("type") or "").lower() == "password" or
             (i.get("name") or "").lower() in PASS_FIELDS),
            None,
        )
        if not user_field or not pass_field:
            continue
        base_data = {
            i["name"]: i.get("value") or "x"
            for i in form["inputs"]
            if i.get("type") not in ("submit", "button")
        }
        rand_user = f"cyberloka_{secrets.token_hex(4)}@example.invalid"
        common_user = "admin"
        evidence_parts = []
        timing_results: dict[str, float] = {}
        bodies: dict[str, str] = {}
        for label, user in (("invalid", rand_user), ("common", common_user)):
            data = {**base_data, user_field: user, pass_field: "Wrong" + secrets.token_hex(3)}
            t0 = time.monotonic()
            r = (client.post(action, data=data) if method == "post"
                 else client.get(action, params=data))
            timing_results[label] = time.monotonic() - t0
            bodies[label] = (r.text or "").lower() if r is not None else ""
        # Marker berbeda?
        inv_body = bodies.get("invalid", "")
        com_body = bodies.get("common", "")
        if inv_body and com_body and inv_body != com_body:
            inv_user_hit = any(m in inv_body for m in INVALID_USER_MARKERS)
            inv_pass_hit = any(m in com_body for m in INVALID_PASS_MARKERS)
            if inv_user_hit or inv_pass_hit or abs(len(inv_body) - len(com_body)) > 200:
                evidence_parts.append(
                    f"len_invalid_user={len(inv_body)}, len_common_user={len(com_body)}"
                )
        # Timing > 250ms berbeda
        if timing_results:
            dt = abs(timing_results.get("invalid", 0) - timing_results.get("common", 0))
            if dt > 0.25:
                evidence_parts.append(
                    f"timing_invalid={timing_results['invalid']:.2f}s vs common={timing_results['common']:.2f}s"
                )
        if evidence_parts:
            findings.append(
                Finding(
                    module="session",
                    title="Indikasi account enumeration di endpoint login",
                    severity=Severity.MEDIUM,
                    description=(
                        "Respons (panjang/marker/timing) terhadap user yang tidak ada "
                        "berbeda dari user yang umum. Attacker dapat memetakan akun "
                        "sebelum brute-force."
                    ),
                    target=action,
                    evidence=" | ".join(evidence_parts),
                    cwe="CWE-204",
                    confidence="tentative",
                    remediation=(
                        "Pakai pesan generik: 'Email atau password salah'. Samakan "
                        "waktu respons (constant-time compare). Tambahkan rate-limit "
                        "+ captcha pada endpoint login."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                    ],
                )
            )
    return findings


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        forms = _login_forms(config)
        findings.extend(_check_login_over_http(client, target, forms))
        findings.extend(_check_session_cookie_attrs(client, target))
        findings.extend(_check_session_id_quality(client, target))
        if forms:
            findings.extend(_check_session_fixation(client, forms))
            findings.extend(_check_account_enum(client, forms))
    finally:
        client.close()
    return findings
