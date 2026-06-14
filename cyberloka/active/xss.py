"""Reflected XSS — verification-first (raw-markup reflection + executable context).

Masalah pendekatan lama: cuma `payload in body`. Refleksi bisa berada di konteks
yang TIDAK dieksekusi browser (di dalam `<textarea>`, komentar, `<title>`), atau
di-encode di tempat lain. Itu bukan XSS yang bisa disusupi.

Pendekatan baru: hanya lapor bila karakter pemecah markup dipantulkan MENTAH
(tidak di-encode) DAN berada di konteks yang benar-benar dapat dieksekusi.
"""
from __future__ import annotations

import secrets

from cyberloka.active._helpers import (
    candidate_urls,
    fuzz_forms,
    param_names,
    replace_param,
)
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate


def _in_safe_context(body: str, idx: int) -> bool:
    before = body[:idx].lower()

    def _open(open_tag: str, close_tag: str) -> bool:
        return before.rfind(open_tag) > before.rfind(close_tag)

    return _open("<textarea", "</textarea>") or _open("<!--", "-->") or _open("<title", "</title>")


def _xss_finding(param: str, target_url: str, snippet: str, is_form: bool) -> Finding:
    where = f"field form `{param}`" if is_form else f"parameter `{param}`"
    return Finding(
        module="xss",
        title=f"Reflected XSS TERVERIFIKASI pada {where}",
        severity=Severity.HIGH,
        confidence="confirmed",
        description=(
            "Karakter pemecah markup (`<`, `>`, `\"`) dipantulkan ke body HTML tanpa di-escape, "
            "di konteks yang dapat dieksekusi browser. Attacker dapat menjalankan JavaScript "
            "arbitrer di sesi korban."
        ),
        target=target_url,
        evidence=snippet,
        cwe="CWE-79",
        remediation=(
            "Lakukan output encoding kontekstual (HTML entity encode untuk konten HTML, JS-encode "
            "untuk <script>, URL-encode untuk atribut href). Gunakan template auto-escape (Jinja2, "
            "React JSX). Tambahkan CSP ketat sebagai pertahanan."
        ),
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    )


def _verify_body(body: str, needle: str) -> str | None:
    if needle not in body:
        return None
    idx = body.find(needle)
    if _in_safe_context(body, idx):
        return None
    return truncate(body[max(0, idx - 80): idx + len(needle) + 80], 240)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for scan_url in candidate_urls(target, config, "q", "test"):
            for param in param_names(scan_url):
                token = secrets.token_hex(4)
                breaker = f'"><svg/onload=clk{token}>'
                needle = f"<svg/onload=clk{token}>"
                mutated = replace_param(scan_url, param, breaker)
                resp = client.get(mutated)
                if resp is None:
                    continue
                if "html" not in resp.headers.get("Content-Type", "").lower():
                    continue
                snippet = _verify_body(resp.text or "", needle)
                if snippet:
                    findings.append(_xss_finding(param, mutated, snippet, is_form=False))

        token = secrets.token_hex(4)
        breaker = f'"><svg/onload=clk{token}>'
        needle = f"<svg/onload=clk{token}>"
        for field, action, resp in fuzz_forms(client, config, breaker):
            if "html" not in resp.headers.get("Content-Type", "").lower():
                continue
            snippet = _verify_body(resp.text or "", needle)
            if snippet:
                findings.append(_xss_finding(field, action, snippet, is_form=True))
    finally:
        client.close()
    return findings
