"""Reflected XSS dengan context-aware confirmation.

5 context payload (html-tag, img-onerror, svg-onload, attr-break, js-break),
masing-masing punya regex yang **wajib match** dalam konteks executable.
Reflection yang ter-encode (mis. ``&lt;script&gt;``) di-skip — itu aman.
Setiap hit direproduksi 1x untuk dapat ``confidence=confirmed``.
"""
from __future__ import annotations

import html
import re
import secrets

from cyberloka.active._helpers import (
    append_param,
    candidate_params,
    iter_param_urls,
)
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

CTYPE_HTML_RE = re.compile(r"text/html|application/xhtml", re.I)


def _build_payloads(token: str) -> list[tuple[str, str, "re.Pattern[str]"]]:
    return [
        ("html-tag",
         f"<sCript>cyberloka{token}</ScRipt>",
         re.compile(rf"<\s*script[^>]*>[^<]*cyberloka{token}", re.I)),
        ("img-onerror",
         f"<imG src=x onerror=cyberloka{token}>",
         re.compile(rf"<\s*img[^>]+onerror[^>]*cyberloka{token}", re.I)),
        ("svg-onload",
         f'"><svg/onload=cyberloka{token}>',
         re.compile(rf"<\s*svg[^>]*onload[^>]*cyberloka{token}", re.I)),
        ("attr-break",
         f'" onmouseover="cyberloka{token}" x="',
         re.compile(rf'\bonmouseover\s*=\s*"\s*cyberloka{token}', re.I)),
        ("js-break",
         f"';cyberloka{token}//",
         re.compile(rf"['\"]\s*;\s*cyberloka{token}\s*//", re.I)),
    ]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    seen: set[str] = set()
    try:
        url = target.base_url
        if "?" not in url:
            for cand in candidate_params(url, ("q", "search", "id", "name", "term", "keyword")):
                url = append_param(url, cand, "test")
                break

        token = secrets.token_hex(4)
        for label, payload, regex in _build_payloads(token):
            for param, mutated in iter_param_urls(url, payload):
                if param in seen:
                    continue
                resp = client.get(mutated)
                if resp is None:
                    continue
                ctype = resp.headers.get("Content-Type", "")
                if not CTYPE_HTML_RE.search(ctype):
                    continue
                body = resp.text or ""
                if f"cyberloka{token}" not in body:
                    continue
                # Encoded reflection only -> safe.
                if html.escape(payload) in body and not regex.search(body):
                    continue
                if not regex.search(body):
                    continue

                resp2 = client.get(mutated)
                confidence = (
                    "confirmed"
                    if resp2 is not None and regex.search(resp2.text or "")
                    else "firm"
                )

                idx = body.lower().find(f"cyberloka{token}".lower())
                snippet = truncate(body[max(0, idx - 100):idx + 160], 280)

                findings.append(
                    Finding(
                        module="xss",
                        title=f"Reflected XSS ({label}) terkonfirmasi pada parameter `{param}`",
                        severity=Severity.HIGH,
                        description=(
                            "Payload HTML/JS dipantulkan ke body response dalam konteks "
                            "executable (tag/atribut/script-block) tanpa output encoding. "
                            "Attacker dapat mencuri sesi, melakukan defacement, atau mengirim "
                            "request berhak atas nama korban."
                        ),
                        target=mutated,
                        evidence=f"context={label}\npayload={payload}\n\nsnippet:\n{snippet}",
                        cwe="CWE-79",
                        confidence=confidence,
                        urls=[mutated],
                        remediation=(
                            "Lakukan output encoding kontekstual (HTML entity encode untuk "
                            "konten HTML, JS-encode untuk konteks <script>, URL-encode untuk "
                            "atribut href/src). Gunakan template engine yang auto-escape. "
                            "Tambahkan CSP yang ketat sebagai pertahanan kedua."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        ],
                    )
                )
                seen.add(param)
                break
    finally:
        client.close()
    return findings
