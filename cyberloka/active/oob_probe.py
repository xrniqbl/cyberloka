"""Blind SSRF confirmation via out-of-band (OAST) callbacks.

Double-gated by `config.authorized` + `config.oob_url`. Injects a benign
collaborator URL into URL-like parameters and confirms the server made an
outbound request by polling the collaborator. No payloads, no exploitation:
a confirmed hit only proves the target fetched a URL we supplied.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.oob import OOBClient
from cyberloka.recon.crawler import get_state

URL_PARAM_HINTS = (
    "url", "uri", "redirect", "next", "image", "fetch", "dest", "callback",
    "src", "target", "feed", "host", "webhook", "link", "load", "proxy",
)


def _candidates(base_url: str, urls: list[str]) -> list[str]:
    pool = list(dict.fromkeys([base_url] + list(urls)))
    out = []
    for u in pool:
        q = urlparse(u).query
        if not q:
            continue
        for k, _ in parse_qsl(q, keep_blank_values=True):
            if any(h in k.lower() for h in URL_PARAM_HINTS):
                out.append(u)
                break
    return out[:10]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if not config.authorized or not config.oob_url:
        return findings
    state = get_state(config)
    urls = state.param_urls if state else []
    candidates = _candidates(target.base_url, urls)
    if not candidates:
        return findings
    oob = OOBClient(config.oob_url, timeout=config.timeout)
    client = HttpClient(config)
    try:
        for url in candidates:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            for i, (k, _) in enumerate(params):
                if not any(h in k.lower() for h in URL_PARAM_HINTS):
                    continue
                token = oob.new_token()
                new = list(params)
                new[i] = (k, oob.payload_url(token))
                mutated = urlunparse(parsed._replace(query=urlencode(new)))
                client.get(mutated)
                hits = oob.wait_for_hit(token)
                if hits:
                    h = hits[0]
                    findings.append(Finding(
                        module="oob_probe",
                        title=f"Blind SSRF terkonfirmasi via callback OOB (param `{k}`)",
                        severity=Severity.HIGH,
                        confidence="confirmed",
                        description=(
                            "Server membuat request keluar ke URL yang dikontrol "
                            "penguji (collaborator OOB) ketika parameter diisi URL "
                            "eksternal. Ini membuktikan Server-Side Request Forgery "
                            "buta: tidak ada refleksi di respons, tapi callback "
                            "benar-benar diterima collaborator."
                        ),
                        target=mutated,
                        evidence=(
                            f"collaborator menerima {len(hits)} hit untuk token "
                            f"`{token}` (mis. {h.get('method')} dari "
                            f"{h.get('remote')})"
                        ),
                        cwe="CWE-918",
                        remediation=(
                            "Validasi & allowlist host tujuan. Blokir IP "
                            "private/link-local (169.254.0.0/16, 127.0.0.0/8, dll). "
                            "Tolak skema dan domain di luar daftar izin."
                        ),
                    ))
                    return findings
    finally:
        client.close()
    return findings
