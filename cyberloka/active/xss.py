"""Reflected XSS detection (heuristic)."""
from __future__ import annotations

import secrets

from cyberloka.active._helpers import (
    append_param,
    candidate_urls,
    fuzz_forms,
    iter_param_urls,
)
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        token = secrets.token_hex(4)
        payload = f"<sCript>cyberloka{token}</sCript>"
        pairs = [
            (param, mutated)
            for scan_url in candidate_urls(target, config, "q", "test")
            for param, mutated in iter_param_urls(scan_url, payload)
        ]
        for param, mutated in pairs:
            resp = client.get(mutated)
            if resp is None:
                continue
            body = resp.text or ""
            if payload in body:
                # Strong signal: unescaped reflection of full payload
                ctype = resp.headers.get("Content-Type", "")
                if "html" not in ctype.lower():
                    continue
                idx = body.find(payload)
                snippet = truncate(body[max(0, idx - 80) : idx + len(payload) + 80], 240)
                findings.append(
                    Finding(
                        module="xss",
                        title=f"Reflected XSS pada parameter `{param}`",
                        severity=Severity.HIGH,
                        description=(
                            "Payload HTML/JS yang dikirim lewat parameter URL dipantulkan "
                            "tanpa di-escape ke body response, memungkinkan eksekusi script "
                            "di browser korban."
                        ),
                        target=mutated,
                        evidence=snippet,
                        cwe="CWE-79",
                        remediation=(
                            "Lakukan output encoding kontekstual (HTML entity encode untuk "
                            "konten HTML, JS-encode untuk konteks <script>, URL-encode untuk "
                            "atribut href). Gunakan template engine yang auto-escape (Jinja2 "
                            "auto-escape, React JSX). Tambahkan CSP yang ketat sebagai pertahanan."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        ],
                    )
                )
        for field, action, resp in fuzz_forms(client, config, payload):
            body = resp.text or ""
            if payload not in body:
                continue
            if "html" not in resp.headers.get("Content-Type", "").lower():
                continue
            idx = body.find(payload)
            snippet = truncate(body[max(0, idx - 80): idx + len(payload) + 80], 240)
            findings.append(Finding(
                module="xss",
                title=f"Reflected XSS pada field form `{field}`",
                severity=Severity.HIGH,
                description=(
                    "Payload HTML/JS yang dikirim lewat field form dipantulkan tanpa "
                    "di-escape ke body response, memungkinkan eksekusi script di browser."
                ),
                target=action,
                evidence=snippet,
                cwe="CWE-79",
                remediation=(
                    "Output encoding kontekstual + template auto-escape; jangan render "
                    "input user mentah. Tambahkan CSP ketat."
                ),
                references=["https://owasp.org/www-community/attacks/xss/"],
            ))
    finally:
        client.close()
    return findings
