"""Open redirect — verification-first.

Hanya lapor bila server BENAR-BENAR mengembalikan redirect 3xx ke host attacker
(termasuk uji protocol-relative `//host`). Parameter tanpa nama-hint wajib
dikonfirmasi dua bentuk payload agar tak salah klaim.
"""
from __future__ import annotations

from urllib.parse import urlparse

from cyberloka.active._helpers import candidate_urls, param_names, replace_param
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

REDIRECT_PARAM_HINTS = (
    "next", "url", "redirect", "redir", "return", "returnto", "rurl", "dest",
    "destination", "continue", "to", "goto", "out", "link", "target", "forward",
)
EVIL_HOST = "evil.example.com"
PAYLOADS = [f"https://{EVIL_HOST}/cyberloka", f"//{EVIL_HOST}/cyberloka"]


def _redirects_to_evil(resp) -> str | None:
    if resp is None or resp.status_code not in (301, 302, 303, 307, 308):
        return None
    loc = resp.headers.get("Location", "")
    if not loc:
        return None
    probe = loc if "://" in loc else ("https:" + loc if loc.startswith("//") else loc)
    host = (urlparse(probe).hostname or "").lower()
    if host == EVIL_HOST or host.endswith("." + EVIL_HOST):
        return loc
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        reported: set[tuple[str, str]] = set()
        for scan_url in candidate_urls(target, config, "next", "/home"):
            for param in param_names(scan_url):
                is_hint = any(h in param.lower() for h in REDIRECT_PARAM_HINTS)
                confirmations = []
                for payload in PAYLOADS:
                    mutated = replace_param(scan_url, param, payload)
                    loc = _redirects_to_evil(client.get(mutated, allow_redirects=False))
                    if loc:
                        confirmations.append(f"{payload} -> Location: {loc}")
                need = 1 if is_hint else 2
                key = (scan_url, param)
                if len(confirmations) >= need and key not in reported:
                    reported.add(key)
                    findings.append(
                        Finding(
                            module="redirect",
                            title=f"Open Redirect TERVERIFIKASI pada parameter `{param}`",
                            severity=Severity.MEDIUM,
                            confidence="confirmed",
                            description=(
                                "Server mengembalikan redirect 3xx ke domain eksternal arbitrer yang "
                                "dikontrol penyerang. Bisa dipakai untuk phishing yang tampak resmi."
                            ),
                            target=scan_url,
                            evidence=" | ".join(confirmations),
                            cwe="CWE-601",
                            remediation=(
                                "Whitelist destinasi redirect. Bila perlu, gunakan id internal yang "
                                "dipetakan ke URL, atau verifikasi host target ada di daftar diizinkan."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
                            ],
                        )
                    )
    finally:
        client.close()
    return findings
