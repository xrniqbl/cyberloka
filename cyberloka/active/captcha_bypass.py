"""Captcha bypass probe (token replay, empty token, common bypass)."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

CAPTCHA_FIELDS = re.compile(
    r"(g-recaptcha-response|h-captcha-response|cf-turnstile-response|captcha[-_]?token|recaptcha)",
    re.I,
)
SUCCESS_HINT = ("welcome", "berhasil", "logged in", "dashboard", "sukses")
CAPTCHA_FAIL = ("captcha", "verifikasi", "verify", "robot")


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings
    forms_with_captcha = []
    for f in s.forms:
        for i in f["inputs"]:
            if CAPTCHA_FIELDS.search(i.get("name", "") or ""):
                forms_with_captcha.append(f); break
    if not forms_with_captcha:
        return findings

    client = HttpClient(config)
    try:
        for form in forms_with_captcha[:2]:
            captcha_field = next((i for i in form["inputs"]
                                  if CAPTCHA_FIELDS.search(i.get("name", "") or "")), None)
            if not captcha_field:
                continue
            base = {i["name"]: (i.get("value") or "x") for i in form["inputs"]
                    if i.get("type") not in ("submit", "button")}
            method = (form.get("method") or "post").lower()

            for label, value in [
                ("kosong", ""),
                ("nol", "0"),
                ("'true'", "true"),
                ("nilai duplikat dari static", "01a01b" * 10),
            ]:
                data = {**base, captcha_field["name"]: value}
                r = (client.post(form["action"], data=data) if method == "post"
                     else client.get(form["action"], params=data))
                if r is None:
                    continue
                body = (r.text or "").lower()
                # Form diterima TANPA error captcha = bypass berhasil
                if r.status_code in (200, 302) and \
                   not any(c in body for c in CAPTCHA_FAIL) and \
                   any(s_ in body for s_ in SUCCESS_HINT):
                    findings.append(Finding(
                        module="captcha_bypass", target=form["action"],
                        title=f"Captcha tampak dapat di-bypass dengan {label}",
                        severity=Severity.HIGH,
                        description=("Form dengan captcha menerima nilai captcha yang invalid "
                                     "tanpa error verifikasi. Indikasi server tidak verifikasi "
                                     "token captcha ke API Google/hCaptcha/Turnstile."),
                        evidence=f"captcha={value!r} -> status {r.status_code}",
                        cwe="CWE-799", confidence="tentative",
                        remediation=("Server WAJIB call siteverify endpoint Google/hCaptcha/"
                                     "Cloudflare dengan secret key. Tolak token kosong/duplikat. "
                                     "Cek field `success: true` di response verifikasi."),
                    ))
                    return findings
    finally:
        client.close()
    return findings
