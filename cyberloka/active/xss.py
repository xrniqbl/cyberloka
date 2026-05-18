"""Reflected XSS detection with context-aware confirmation.

Bukan sekadar mencari token di body. Verifikasi:

1. Token unik ditembakkan dengan beberapa **context payload**:
   ``<script>...`` , ``"><svg onload>``, atribut ``" onmouseover=``, dan JS
   sederhana (``';alert(...);//``).
2. Untuk setiap reflection, cek **konteks**:
   - HTML body? → harus muncul tag/atribut yang bisa eksekusi.
   - Atribut? → harus break-out (kutip ditutup, atribut event baru terbentuk).
   - Script block? → harus muncul setelah string-break (``';``).
3. Cek **encoding**: kalau yang muncul versi ``&lt;script&gt;`` saja → aman,
   bukan vuln.
4. Reproduksi sekali lagi untuk konfirmasi non-flaky.

Hanya yang lulus context check yang dilaporkan HIGH.
"""
from __future__ import annotations

import html
import re
import secrets

from cyberloka.active._helpers import (
    append_param,
    candidate_params,
    iter_param_urls,
    replace_param,
)
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

CTYPE_HTML_RE = re.compile(r"text/html|application/xhtml", re.I)


def _build_payloads(token: str) -> list[tuple[str, str, re.Pattern[str]]]:
    """Return list of (label, payload, must-match-regex)."""
    return [
        (
            "html-tag",
            f"<sCript>cyberloka{token}</ScRipt>",
            re.compile(rf"<\s*script[^>]*>[^<]*cyberloka{token}", re.I),
        ),
        (
            "img-onerror",
            f"<imG src=x onerror=cyberloka{token}>",
            re.compile(rf"<\s*img[^>]+onerror[^>]*cyberloka{token}", re.I),
        ),
        (
            "svg-onload",
            f'"><svg/onload=cyberloka{token}>',
            re.compile(rf"<\s*svg[^>]*onload[^>]*cyberloka{token}", re.I),
        ),
        (
            "attr-break",
            f'" onmouseover="cyberloka{token}" x="',
            re.compile(rf'\bonmouseover\s*=\s*"\s*cyberloka{token}', re.I),
        ),
        (
            "js-break",
            f"';cyberloka{token}//",
            re.compile(rf"['\"]\s*;\s*cyberloka{token}\s*//", re.I),
        ),
    ]


def _is_safely_encoded(body: str, token: str) -> bool:
    """True bila token muncul tapi semua tag-marker sudah ter-escape."""
    if token not in body:
        return False
    # If we can't find ANY raw '<' or '"' near the token, it's encoded.
    for m in re.finditer(re.escape(token), body):
        start = max(0, m.start() - 4)
        end = min(len(body), m.end() + 4)
        chunk = body[start:end]
        if "<" in chunk or '"' in chunk or "'" in chunk:
            return False
    return True


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
                # Quick exit: token not present
                if f"cyberloka{token}" not in body:
                    continue
                # Encoded only? safe.
                if html.escape(payload) in body and not regex.search(body):
                    continue
                if not regex.search(body):
                    # Token present but not in executable context.
                    continue
                # Reproduce
                resp2 = client.get(mutated)
                if resp2 is None or not regex.search(resp2.text or ""):
                    confidence = "firm"
                else:
                    confidence = "confirmed"

                idx = body.lower().find(f"cyberloka{token}".lower())
                snippet = truncate(body[max(0, idx - 100): idx + 160], 280)

                findings.append(
                    Finding(
                        module="xss",
                        title=f"Reflected XSS ({label}) terkonfirmasi pada parameter `{param}`",
                        severity=Severity.HIGH,
                        description=(
                            "Payload HTML/JS dipantulkan ke body response dalam konteks "
                            "executable (tag/atribut/script-block) tanpa output encoding. "
                            "Attacker dapat mencuri sesi, melakukan defacement, atau "
                            "mengirim request berhak atas nama korban."
                        ),
                        target=mutated,
                        evidence=f"context={label}\npayload={payload}\n\nsnippet:\n{snippet}",
                        cwe="CWE-79",
                        confidence=confidence,
                        remediation=(
                            "Lakukan output encoding kontekstual (HTML entity encode untuk "
                            "konten HTML, JS-encode untuk konteks <script>, URL-encode untuk "
                            "atribut href/src). Gunakan template engine yang auto-escape "
                            "(Jinja2 auto-escape, React JSX, Vue interpolation). Tambahkan "
                            "CSP yang ketat (`default-src 'self'; script-src 'self'`) sebagai "
                            "pertahanan jika encoding terlewat."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        ],
                    )
                )
                seen.add(param)
                break  # next payload
    finally:
        client.close()
    return findings
