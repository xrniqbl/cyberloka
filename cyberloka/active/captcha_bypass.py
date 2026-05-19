"""Captcha bypass probe — strict-validation v0.10.4.

Sebelumnya: kalau body memuat ``welcome``/``dashboard`` setelah submit
form dengan captcha kosong, flag bypass. Banyak halaman home memuat
"welcome" sehingga FP tinggi.

Sekarang konfirmasi:
- Baseline: kirim form dengan captcha **dummy** (token random) +
  kredensial pasti-salah. Body baseline TIDAK boleh memuat success hint.
- Test: submit dengan captcha kosong/0/'true'. Bypass dianggap berhasil
  HANYA bila response untuk test berbeda signifikan dari baseline DAN
  memuat success hint TANPA failure hint captcha.
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
    body_similarity,
    build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

CAPTCHA_FIELDS = re.compile(
    r"(g-recaptcha-response|h-captcha-response|cf-turnstile-response|"
    r"captcha[-_]?token|recaptcha)",
    re.I,
)
SUCCESS_HINT = ("welcome", "berhasil", "logged in", "dashboard", "sukses")
CAPTCHA_FAIL = ("captcha", "verifikasi", "verify", "robot")


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings
    forms_with_captcha: list[dict] = []
    for f in s.forms:
        for i in f["inputs"]:
            if CAPTCHA_FIELDS.search(i.get("name", "") or ""):
                forms_with_captcha.append(f)
                break
    if not forms_with_captcha:
        return findings

    client = HttpClient(config)
    try:
        for form in forms_with_captcha[:2]:
            captcha_field = next(
                (i for i in form["inputs"]
                 if CAPTCHA_FIELDS.search(i.get("name", "") or "")),
                None,
            )
            if not captcha_field:
                continue
            base_inputs = {
                i["name"]: (i.get("value") or "x")
                for i in form["inputs"]
                if i.get("type") not in ("submit", "button")
            }
            method = (form.get("method") or "post").lower()

            # Baseline: full random data + captcha dummy
            tag = secrets.token_hex(4)
            baseline_data = {**base_inputs}
            for i in form["inputs"]:
                name = i.get("name", "")
                t = (i.get("type") or "").lower()
                if t == "password":
                    baseline_data[name] = f"wrong_{tag}"
                elif "email" in name.lower() or "user" in name.lower():
                    baseline_data[name] = f"cyberloka_{tag}@invalid.local"
            baseline_data[captcha_field["name"]] = (
                f"cyberloka-baseline-token-{secrets.token_hex(4)}"
            )
            base_resp = (
                client.post(form["action"], data=baseline_data) if method == "post"
                else client.get(form["action"], params=baseline_data)
            )
            if base_resp is None:
                continue
            base_body = (base_resp.text or "").lower()
            # Kalau baseline saja sudah memuat success hint, oracle tidak valid.
            if any(s_ in base_body for s_ in SUCCESS_HINT):
                continue

            for label, value in [("kosong", ""), ("nol", "0"), ("string 'true'", "true")]:
                data = {**baseline_data, captcha_field["name"]: value}
                r = (
                    client.post(form["action"], data=data) if method == "post"
                    else client.get(form["action"], params=data)
                )
                if r is None:
                    continue
                body = (r.text or "").lower()
                if r.status_code not in (200, 302):
                    continue
                if any(c in body for c in CAPTCHA_FAIL):
                    continue
                if not any(s_ in body for s_ in SUCCESS_HINT):
                    continue
                # Body harus berbeda signifikan dari baseline.
                sim = body_similarity(base_body, body)
                if sim > 0.92:
                    continue

                proof = ValidationProof(
                    method="random-baseline+similarity-diff",
                    confirmed=True,
                    steps=[
                        f"Baseline (captcha dummy random) -> response TIDAK memuat success hint.",
                        f"Probe (captcha={value!r}) -> response MEMUAT success hint, "
                        "tanpa pesan error captcha.",
                        f"sim(base, probe) = {sim:.2f} (< 0.92 -> berbeda signifikan).",
                    ],
                    samples=[f"captcha={value!r}, status={r.status_code}, sim={sim:.2f}"],
                )
                findings.append(Finding(
                    module="captcha_bypass", target=form["action"],
                    title=f"Captcha bypass terkonfirmasi dengan {label}",
                    severity=Severity.HIGH,
                    description=(
                        "Form dengan captcha menerima nilai captcha invalid "
                        "TANPA error verifikasi DAN memberi response sukses "
                        "yang berbeda dari baseline (captcha dummy). Indikasi "
                        "server tidak benar-benar verifikasi token captcha ke "
                        "API Google/hCaptcha/Turnstile."
                    ),
                    evidence=f"captcha={value!r} -> status {r.status_code}; sim(base,probe)={sim:.2f}",
                    cwe="CWE-799",
                    confidence="confirmed",
                    urls=[form["action"]],
                    remediation=(
                        "Server WAJIB call siteverify endpoint Google/hCaptcha/"
                        "Cloudflare dengan secret key. Tolak token kosong/duplikat. "
                        "Cek field `success: true` di response verifikasi."
                    ),
                    extra=build_extra(proof=proof),
                ))
                return findings
    finally:
        client.close()
    return findings
