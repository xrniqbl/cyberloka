"""Naive SSRF probe on URL-shaped query params (passive heuristic)."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

URL_PARAM_HINTS = ("url", "uri", "redirect", "next", "image", "fetch", "dest", "callback")
PROBE_URL = "http://127.0.0.1:80/"


def _candidates(base_url: str, urls: list[str]) -> list[str]:
    pool = set([base_url] + urls)
    matches: list[str] = []
    for u in pool:
        q = urlparse(u).query
        if not q:
            continue
        for k, _ in parse_qsl(q, keep_blank_values=True):
            if any(h in k.lower() for h in URL_PARAM_HINTS):
                matches.append(u)
                break
    return matches[:15]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    state = get_state(config)
    urls = state.param_urls if state else []
    candidates = _candidates(target.base_url, urls)
    if not candidates:
        return []
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for url in candidates:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            for i, (k, _) in enumerate(params):
                if not any(h in k.lower() for h in URL_PARAM_HINTS):
                    continue
                new = list(params)
                new[i] = (k, PROBE_URL)
                mutated = urlunparse(parsed._replace(query=urlencode(new)))
                r = client.get(mutated)
                if r is None:
                    continue
                # Heuristic: server fetched the URL and returned content from it.
                body = r.text or ""
                if r.status_code in (200, 301, 302) and (
                    "127.0.0.1" in body or "localhost" in body or "<title>" in body.lower()[:200]
                ):
                    findings.append(
                        Finding(
                            module="ssrf",
                            title=f"Potensi SSRF pada parameter `{k}`",
                            severity=Severity.HIGH,
                            description=(
                                "Server tampaknya fetch URL yang dikontrol klien. Penyerang "
                                "bisa menyentuh service internal (mis. metadata cloud)."
                            ),
                            target=mutated,
                            evidence=f"HTTP {r.status_code} · body[0:200]={body[:200]!r}",
                            cwe="CWE-918",
                            remediation=(
                                "Whitelist domain target, blokir IP private (RFC1918, "
                                "169.254.0.0/16), tolak skema selain http(s), batasi redirect."
                            ),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
                            ],
                        )
                    )
                    break
    finally:
        client.close()
    return findings
