"""Password policy enforcement scanner.

Modul ini menguji apakah endpoint **register / change-password / reset**
menerima password lemah yang seharusnya ditolak. Server yang menerima
`12345` atau `password` membuat akun pelanggan rentan brute-force massal.

Strategi:
    1. **Endpoint discovery** dari crawler — form yang punya field
       `password` + `email`/`username` (dan biasanya juga `confirm`).
       Plus path generik: /register, /signup, /api/register, /api/signup,
       /daftar, /create-account.

    2. **Probe payload password lemah**:
        ""                  - kosong
        "1"                 - 1 karakter
        "12345"             - numeric pendek umum
        "password"          - top-1 leaked
        "qwerty"            - top-2
        "abc"               - alfabet pendek
        "aaaaa"             - all-same
        "12345678"          - tetap di top-10 leaked
        Kirim sebagai pasangan {password=..., password_confirmation=...}
        + email/username random + field wajib lain dari form.

    3. **Validasi accept-vs-reject**:
        Accept markers (artinya password lolos validasi):
          "berhasil", "success", "registered", "akun dibuat", "verifikasi",
          status 200/201 dengan tidak ada error.
        Reject markers:
          "minimal", "at least", "weak", "lemah", "syarat", "must be",
          "password too short", "common password", "validation".
       Kalau **>=2 password ekstrem** lolos -> finding.

    4. **Validasi tambahan**:
       Re-register dengan password yang sangat aman ("Cyberloka!Test#2026")
       sebagai control. Bila respons SAMA dengan password lemah, server
       memang tidak validasi panjang/komposisi.

Setiap finding memuat reverify marker.
"""
from __future__ import annotations

import random
import re
import string
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state

REGISTER_HINTS = re.compile(
    r"(register|signup|sign[-_]?up|daftar|create[-_]?account|new[-_]?user)",
    re.I,
)
PASSWORD_FIELD_RE = re.compile(r"password|passwd|pwd|sandi|kata[-_]?sandi", re.I)
EMAIL_FIELD_RE = re.compile(r"email|e[-_]?mail|surel", re.I)
USERNAME_FIELD_RE = re.compile(r"user(?:name)?|nama[-_]?pengguna", re.I)

GENERIC_PATHS = [
    "register", "signup", "sign-up", "daftar", "create-account",
    "api/register", "api/signup", "api/auth/register", "api/users",
    "api/user/register", "user/register",
]

WEAK_PASSWORDS = [
    ("kosong", ""),
    ("1 karakter", "1"),
    ("3 karakter", "abc"),
    ("numeric pendek", "12345"),
    ("kata umum 'password'", "password"),
    ("kata umum 'qwerty'", "qwerty"),
    ("repetisi 'aaaaa'", "aaaaa"),
    ("8-numeric umum", "12345678"),
]
STRONG_PASSWORD = "Cyberl0ka!Test#2026Aa"

ACCEPT_MARKERS = (
    "berhasil", "success", "registered", "akun dibuat", "akun berhasil",
    "welcome", '"status":"ok"', '"success":true', "verification email",
    "verifikasi", "registration complete",
)
REJECT_MARKERS = (
    "minimal", "at least", "minimum", "must be at least",
    "weak password", "password lemah", "password too short", "too short",
    "tidak memenuhi", "syarat password", "common password",
    "password mudah", "must contain", "harus berisi",
    "validation failed", "validation error", "invalid password",
    "passwordtooshort", "passwordtoocommon",
)


def _rand_email() -> str:
    pre = "".join(random.choices(string.ascii_lowercase, k=10))
    return f"cyberloka_{pre}@example.com"


def _rand_username() -> str:
    return "cyberloka_" + "".join(random.choices(string.ascii_lowercase, k=8))


def _candidates(config: ScanConfig) -> list[dict]:
    """Return list of {url, method, inputs}.

    Form yang punya field password + (email|username) dianggap register/
    change-password endpoint."""
    state = get_state(config)
    out: list[dict] = []
    seen: set[str] = set()
    if state:
        for f in state.forms:
            action = f.get("action") or ""
            inputs = f.get("inputs") or []
            has_pwd = any(PASSWORD_FIELD_RE.search(i.get("name", ""))
                          for i in inputs)
            has_id = any(EMAIL_FIELD_RE.search(i.get("name", "")) or
                         USERNAME_FIELD_RE.search(i.get("name", ""))
                         for i in inputs)
            if has_pwd and has_id and action and action not in seen:
                out.append({"url": action,
                            "method": (f.get("method") or "post").upper(),
                            "inputs": inputs})
                seen.add(action)
    return out[:6]


def _build_payload(form: dict, password: str) -> dict:
    """Isi semua field form, override password + email + username."""
    p: dict = {}
    for i in form["inputs"]:
        n = i.get("name", "")
        if not n or i.get("type") in ("submit", "button"):
            continue
        if PASSWORD_FIELD_RE.search(n):
            p[n] = password
        elif EMAIL_FIELD_RE.search(n):
            p[n] = _rand_email()
        elif USERNAME_FIELD_RE.search(n):
            p[n] = _rand_username()
        else:
            p[n] = i.get("value") or "test"
    return p


def _accepted(status: int, body: str) -> bool:
    body_low = body.lower()
    if any(m in body_low for m in REJECT_MARKERS):
        return False
    if status >= 400:
        return False
    return any(m in body_low for m in ACCEPT_MARKERS) or status in (200, 201)


def _try_register(client: HttpClient, form: dict, password: str
                  ) -> tuple[int, str] | None:
    payload = _build_payload(form, password)
    r = client.post(form["url"], data=payload)
    if r is None:
        return None
    return r.status_code, (r.text or "")


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    forms = _candidates(config)
    if not forms:
        # fallback: probe path generik dengan body JSON minimum
        base = target.origin + "/"
        for path in GENERIC_PATHS:
            url = urljoin(base, path)
            forms.append({
                "url": url, "method": "POST",
                "inputs": [
                    {"name": "email", "type": "email"},
                    {"name": "password", "type": "password"},
                    {"name": "password_confirmation", "type": "password"},
                    {"name": "username", "type": "text"},
                ],
            })
        forms = forms[:5]
    if not forms:
        return findings

    client = HttpClient(config)
    try:
        for form in forms:
            # Kontrol: kirim password kuat dulu untuk lihat response baseline.
            ctrl = _try_register(client, form, STRONG_PASSWORD)
            if ctrl is None:
                continue
            if ctrl[0] in (404, 410):
                continue
            ctrl_accepted = _accepted(*ctrl)
            # Bila bahkan password kuat ditolak (misal email sudah dipakai
            # / endpoint memang protected) -> skip.
            if not ctrl_accepted:
                # Tapi tetap test 1 password lemah untuk konfirmasi reject
                # konsisten.
                test = _try_register(client, form, WEAK_PASSWORDS[0][1])
                if test is None:
                    continue
                # Server selalu reject -> tidak bisa simpulkan policy.
                # skip diam-diam.
                continue

            # Server menerima password kuat. Sekarang test password lemah.
            weak_accepted: list[str] = []
            for label, pw in WEAK_PASSWORDS:
                res = _try_register(client, form, pw)
                if res is None:
                    continue
                if _accepted(*res):
                    weak_accepted.append(f"{label}={pw!r}")
                    if len(weak_accepted) >= 3:
                        break  # cukup bukti

            if len(weak_accepted) >= 2:
                # Kalau >= 2 password ekstrem diterima, hampir pasti tidak
                # ada policy.
                findings.append(Finding(
                    module="password_policy",
                    title="Password policy lemah / tidak ter-enforce",
                    severity=Severity.HIGH if len(weak_accepted) >= 4
                             else Severity.MEDIUM,
                    description=(
                        "Endpoint registrasi/change-password menerima "
                        "password yang sangat lemah. Akun pelanggan jadi "
                        "sasaran credential stuffing & brute-force massal."
                    ),
                    target=form["url"],
                    evidence=truncate(
                        f"strong_pwd_accepted=True; "
                        f"weak_accepted={weak_accepted}",
                        260,
                    ),
                    cwe="CWE-521",
                    confidence="firm",
                    remediation=(
                        "Tetapkan policy minimum: panjang ≥ 12 karakter, "
                        "wajib mix huruf-besar/kecil/angka/simbol, dan "
                        "tolak password yang masuk daftar bocor "
                        "(haveibeenpwned k-anonymity API). Validasi di "
                        "server, jangan hanya client-side. Pertimbangkan "
                        "passphrase / passkey (WebAuthn) untuk akun penting."
                    ),
                    references=[
                        "https://owasp.org/www-project-application-security-verification-standard/",
                        "https://pages.nist.gov/800-63-3/sp800-63b.html",
                        "https://haveibeenpwned.com/Passwords",
                    ],
                    extra={"reverify": {"status": (200, 201),
                                        "marker": "berhasil", "in_body": True,
                                        "method": "POST"}},
                ))
            elif len(weak_accepted) == 1:
                # Borderline: cukup mencurigakan untuk dilaporkan tentative.
                findings.append(Finding(
                    module="password_policy",
                    title="Password lemah diterima (1 dari beberapa test)",
                    severity=Severity.LOW,
                    description=(
                        "Salah satu test password lemah lolos validasi. "
                        "Bukan bukti kuat, tapi periksa ulang policy."
                    ),
                    target=form["url"],
                    evidence=f"weak_accepted={weak_accepted}",
                    cwe="CWE-521",
                    confidence="tentative",
                    remediation=(
                        "Audit aturan validasi password server-side. "
                        "Pastikan tidak ada bypass via field yang berbeda."
                    ),
                ))
    finally:
        client.close()
    return findings
