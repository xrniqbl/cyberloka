"""Reflected XSS detection (heuristic)."""
from __future__ import annotations

import secrets

from cyberloka.active._helpers import append_param, iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        url = target.base_url
        if "?" not in url:
            url = append_param(url, "q", "test")

        token = secrets.token_hex(4)
        payload = f"<sCript>cyberloka{token}</sCript>"
        for param, mutated in iter_param_urls(url, payload):
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
    finally:
        client.close()
    return findings
