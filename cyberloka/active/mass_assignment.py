"""Mass-assignment probe — strict-validation v0.10.4.

Sebelumnya: kalau body memuat field privilege setelah register, flag.
Banyak halaman menampilkan kata "role" atau "admin" di copy/UI sehingga
echoback-only check menghasilkan FP.

Sekarang konfirmasi:
- Baseline: register tanpa field privilege ekstra. Catat apakah body
  memuat marker tersebut.
- Test: register dengan field privilege ekstra. Hanya flag kalau MARKER
  PRIVILEGE muncul di response test TAPI TIDAK muncul di baseline.
"""
from __future__ import annotations

import re
import secrets

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

REGISTER_HINT = re.compile(r"register|signup|sign-?up|daftar|create-?account|profile", re.I)
PRIVILEGE_FIELDS = [
    ("is_admin", "true"),
    ("isAdmin", "true"),
    ("role", "admin"),
    ("user_role", "admin"),
    ("is_staff", "true"),
    ("admin", "1"),
    ("verified", "true"),
    ("email_verified", "true"),
]
LOGIN_FIELDS_USER = ("username", "email", "user", "userid", "login")


def _candidate_forms(config: ScanConfig) -> list[dict]:
    state = get_state(config)
    if not state:
        return []
    out = []
    for f in state.forms:
        action_low = (f.get("action") or "").lower()
        if (REGISTER_HINT.search(action_low) and
                any((i.get("type") or "").lower() == "password" for i in f["inputs"])):
            out.append(f)
    return out


def _build_base(form: dict) -> tuple[dict, str | None, str | None]:
    base = {
        i["name"]: i.get("value") or "x"
        for i in form["inputs"]
        if i.get("type") not in ("submit", "button")
    }
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
    return base, user_field, pass_field


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    forms = _candidate_forms(config)
    if not forms:
        return findings
    client = HttpClient(config)
    try:
        for form in forms[:2]:
            base, user_field, pass_field = _build_base(form)
            method = (form.get("method") or "post").lower()
            action = form["action"]

            tag = secrets.token_hex(4)
            base_data = {**base}
            if user_field:
                base_data[user_field] = f"cyberloka_base_{tag}@example.invalid"
            if pass_field:
                base_data[pass_field] = f"Cybr0loka!_{tag}"
            base_resp = (
                client.post(action, data=base_data) if method == "post"
                else client.get(action, params=base_data)
            )
            if base_resp is None:
                continue
            base_body = (base_resp.text or "").lower()

            for field, value in PRIVILEGE_FIELDS[:6]:
                tag2 = secrets.token_hex(4)
                payload = {**base}
                if user_field:
                    payload[user_field] = f"cyberloka_test_{tag2}@example.invalid"
                if pass_field:
                    payload[pass_field] = f"Cybr0loka!_{tag2}"
                payload[field] = value

                r = (
                    client.post(action, data=payload) if method == "post"
                    else client.get(action, params=payload)
                )
                if r is None or r.status_code not in (200, 201, 302):
                    continue
                body = (r.text or "").lower()
                if any(s in body for s in ("error", "invalid", "gagal", "salah")):
                    continue
                field_in_test = field.lower() in body
                value_in_test = (
                    isinstance(value, str) and value.lower() in body
                )
                field_in_base = field.lower() in base_body
                value_in_base = (
                    isinstance(value, str) and value.lower() in base_body
                )
                privilege_unique = (
                    (field_in_test and not field_in_base)
                    or (value_in_test and not value_in_base)
                )
                if not privilege_unique:
                    continue
                proof = ValidationProof(
                    method="echoback-unique-to-test",
                    confirmed=True,
                    steps=[
                        f"Baseline register tanpa `{field}` -> body baseline tidak memuat field/value.",
                        f"Probe register dengan `{field}={value}` -> body test memuat field/value.",
                        "Field privilege muncul HANYA setelah dikirim oleh klien -> "
                        "server tidak whitelisting input.",
                    ],
                    samples=[f"{field}={value}, status={r.status_code}"],
                )
                findings.append(Finding(
                    module="mass_assignment",
                    title=(
                        f"Mass assignment terkonfirmasi: form `{action}` "
                        f"merefleksi field privilege ekstra `{field}={value}`"
                    ),
                    severity=Severity.HIGH,
                    description=(
                        "Form register/profile menerima field privilege ekstra dan "
                        "merefleksinya di response, sementara baseline tanpa field "
                        "tersebut tidak. Verifikasi manual apakah akun yang baru "
                        "dibuat benar-benar punya role admin / verified."
                    ),
                    target=action,
                    evidence=(
                        f"field={field}={value}; status={r.status_code}; "
                        "echoback unique to test (not present in baseline)"
                    ),
                    cwe="CWE-915",
                    confidence="confirmed",
                    urls=[action],
                    remediation=(
                        "Whitelist field yang boleh diterima dari klien (allowlist). "
                        "Set role/balance/verified di server-side berdasarkan logic "
                        "internal, jangan ambil dari request body. Pakai DTO/serializer "
                        "yang ketat (Pydantic, Marshmallow, Joi)."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                    ],
                    extra=build_extra(proof=proof),
                ))
                return findings
    finally:
        client.close()
    return findings
