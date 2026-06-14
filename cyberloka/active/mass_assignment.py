"""Mass-assignment probe: send `is_admin=true` / `role=admin` in registration / profile updates."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
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
    ("balance", "9999999"),
    ("saldo", "9999999"),
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


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    forms = _candidate_forms(config)
    if not forms:
        return findings
    client = HttpClient(config)
    try:
        for form in forms[:2]:
            base = {
                i["name"]: i.get("value") or "x"
                for i in form["inputs"]
                if i.get("type") not in ("submit", "button")
            }
            # Fill identity fields with random values
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
            import secrets as _sec
            tag = _sec.token_hex(4)
            if user_field:
                base[user_field] = f"cyberloka_{tag}@example.com"
            if pass_field:
                base[pass_field] = f"Cybr0loka!_{tag}"

            method = (form.get("method") or "post").lower()
            action = form["action"]
            # Kontrol: submit TANPA field privilege. Bila field/nilai sudah muncul di
            # sini, kemunculannya bukan akibat kita mengirimnya.
            ctrl = (client.post(action, data=base) if method == "post"
                    else client.get(action, params=base))
            ctrl_body = (ctrl.text or "").lower() if ctrl is not None else ""
            for field, value in PRIVILEGE_FIELDS[:6]:
                payload = {**base, field: value}
                r = (client.post(action, data=payload) if method == "post"
                     else client.get(action, params=payload))
                if r is None:
                    continue
                body = (r.text or "").lower()
                ok = (
                    r.status_code in (200, 201, 302) and
                    not any(s in body for s in ("error", "invalid", "gagal", "salah"))
                )
                # Refleksi TERSTRUKTUR (`"field": value` / `field=value`) — bukan kata
                # "admin"/"true" yang ada di mana-mana. Harus muncul pada respons payload
                # TAPI absen pada kontrol → bukti field benar-benar diterima/disimpan.
                pat = re.compile(
                    r'["\']?' + re.escape(field) + r'["\']?\s*[:=]\s*["\']?' + re.escape(str(value)),
                    re.I,
                )
                if ok and pat.search(body) and not pat.search(ctrl_body):
                    findings.append(Finding(
                        module="mass_assignment",
                        title=f"Form {form['action']} menerima field tambahan `{field}={value}`",
                        severity=Severity.HIGH,
                        description=(
                            "Form register/profile menerima field privilege ekstra "
                            "yang seharusnya tidak boleh diset oleh user. Verifikasi "
                            "manual apakah akun yang baru dibuat benar-benar punya "
                            "role admin / saldo besar."
                        ),
                        target=action,
                        evidence=f"field={field}={value}; status={r.status_code}; echoback=True",
                        cwe="CWE-915",
                        confidence="tentative",
                        remediation=(
                            "Whitelist field yang boleh diterima dari klien (allowlist). "
                            "Set role/balance/verified di server-side berdasarkan logic "
                            "internal, jangan ambil dari request body. Pakai DTO/serializer "
                            "yang ketat (Pydantic, Marshmallow, Joi)."
                        ),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                        ],
                    ))
                    return findings
    finally:
        client.close()
    return findings
