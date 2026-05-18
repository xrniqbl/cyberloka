"""Open redirect detection - 6 bypass payload, hanya host attacker yg di-flag.

Hanya parameter yang nama-nya cocok REDIRECT_PARAM_HINTS yang diuji
(mengurangi false positive). Coba beberapa bentuk bypass:
1. ``https://evil.example.com``
2. ``//evil.example.com``
3. ``\\\\evil.example.com``
4. URL-encoded
5. ``//google.com@evil.example.com``
6. ``https://evil.example.com%2f.example.com/``

Konfirmasi: parse Location → host harus berakhir di evil.example.com.
"""
from __future__ import annotations

from urllib.parse import urlparse

from cyberloka.active._helpers import iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

REDIRECT_PARAM_HINTS = (
    "next", "url", "redirect", "redir", "return", "returnto", "rurl",
    "dest", "destination", "continue", "to", "target", "checkout_url",
    "callback", "back",
)
EVIL_HOST = "evil.example.com"
PAYLOADS = [
    f"https://{EVIL_HOST}/cyberloka",
    f"//{EVIL_HOST}/cyberloka",
    f"\\\\{EVIL_HOST}/cyberloka",
    f"https:%2f%2f{EVIL_HOST}/cyberloka",
    f"//google.com@{EVIL_HOST}/cyberloka",
    f"https://{EVIL_HOST}%2f.example.com/",
]


def _is_evil(loc: str) -> bool:
    if not loc:
        return False
    cleaned = loc.replace("\\", "/").lstrip()
    if cleaned.startswith("//"):
        cleaned = "http:" + cleaned
    parsed = urlparse(cleaned)
    host = (parsed.hostname or "").lower()
    return host == EVIL_HOST or host.endswith("." + EVIL_HOST)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        url = target.base_url
        if "?" not in url:
            return findings
        seen: set[str] = set()
        for payload in PAYLOADS:
            for param, mutated in iter_param_urls(url, payload):
                if param in seen:
                    continue
                if not any(h in param.lower() for h in REDIRECT_PARAM_HINTS):
                    continue
                resp = client.get(mutated, allow_redirects=False)
                if resp is None or not (300 <= resp.status_code < 400):
                    continue
                loc = resp.headers.get("Location", "")
                if not _is_evil(loc):
                    continue
                resp2 = client.get(mutated, allow_redirects=False)
                confidence = (
                    "confirmed"
                    if resp2 is not None and _is_evil(resp2.headers.get("Location", ""))
                    else "firm"
                )
                findings.append(
                    Finding(
                        module="redirect",
                        title=f"Open Redirect terkonfirmasi pada parameter `{param}`",
                        severity=Severity.MEDIUM,
                        description=(
                            "Server mengembalikan redirect (3xx) ke domain eksternal yang "
                            "dikontrol attacker. Bisa dipakai sebagai komponen phishing yang "
                            "tampak resmi (mis. domain bank → /login?next=evil.com → password "
                            "diketik di halaman attacker), atau bypass filter SSRF."
                        ),
                        target=mutated,
                        evidence=f"payload={payload!r}\nLocation: {loc}",
                        cwe="CWE-601",
                        confidence=confidence,
                        urls=[mutated],
                        remediation=(
                            "Whitelist destinasi redirect (daftar host atau path internal). "
                            "Tolak input yang protocol-relative (`//`). Bila perlu open redirect, "
                            "gunakan id internal yang dipetakan ke URL whitelist."
                        ),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                            "https://cwe.mitre.org/data/definitions/601.html",
                        ],
                    )
                )
                seen.add(param)
                break
    finally:
        client.close()
    return findings
