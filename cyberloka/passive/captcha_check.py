"""Detect missing captcha / bot-protection on sensitive forms."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

SENSITIVE_FORM = re.compile(
    r"login|signin|register|signup|forgot|reset|otp|verify|verifikasi|"
    r"checkout|payment|redeem|kupon|voucher",
    re.I,
)
CAPTCHA_HINTS = re.compile(
    r"recaptcha|hcaptcha|cloudflare-challenge|turnstile|cf-turnstile|"
    r"g-recaptcha|h-captcha|captcha",
    re.I,
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    state = get_state(config)
    if not state or not state.forms:
        return findings
    client = HttpClient(config)
    try:
        seen: set[str] = set()
        for form in state.forms:
            action_low = (form.get("action") or "").lower()
            names = " ".join(i.get("name", "") for i in form["inputs"]).lower()
            text_blob = action_low + " " + names
            if not SENSITIVE_FORM.search(text_blob):
                continue
            page = form.get("action")
            if page in seen:
                continue
            seen.add(page)
            r = client.get(page)
            if r is None:
                continue
            body = r.text or ""
            if CAPTCHA_HINTS.search(body):
                continue
            findings.append(Finding(
                module="captcha_check",
                title=f"Form sensitif tanpa captcha/bot-protection: {form['action']}",
                severity=Severity.LOW,
                description=("Form (login/register/reset/checkout/redeem) tidak menampilkan "
                             "tanda integrasi captcha. Tanpa captcha + tanpa rate-limit kuat, "
                             "endpoint mudah di-brute-force/scrape."),
                target=form["action"],
                evidence=f"fields={names[:120]}",
                cwe="CWE-799", confidence="tentative",
                remediation=("Tambahkan reCAPTCHA v3 / hCaptcha / Cloudflare Turnstile pada "
                             "form sensitif, atau rate-limit per-akun + per-IP yang ketat."),
            ))
            if len(findings) >= 4:
                break
    finally:
        client.close()
    return findings
