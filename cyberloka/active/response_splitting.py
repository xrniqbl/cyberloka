"""HTTP response splitting via Location header injection."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    candidates = list(s.param_urls if s else [])[:5]
    if not candidates:
        return findings
    client = HttpClient(config)
    payload = "%0d%0aSet-Cookie:cyberloka=1"
    try:
        for url in candidates:
            parsed = urlparse(url)
            params = list(parse_qsl(parsed.query))
            for k, _ in params:
                if k.lower() in ("redirect", "next", "url", "return", "to", "back"):
                    new_q = urlencode([(kk, payload if kk == k else vv) for kk, vv in params],
                                      safe="%")
                    mutated = urlunparse(parsed._replace(query=new_q))
                    r = client.get(mutated, allow_redirects=False)
                    if r is None:
                        continue
                    loc = r.headers.get("Location") or ""
                    sc = r.headers.get("Set-Cookie") or ""
                    if "cyberloka=1" in sc.lower() or "set-cookie" in loc.lower():
                        findings.append(Finding(
                            module="response_splitting", target=mutated,
                            title=f"Response splitting via parameter `{k}`",
                            severity=Severity.HIGH,
                            description="Payload CRLF di parameter redirect menambah header response.",
                            evidence=f"Set-Cookie: {sc[:80]}", cwe="CWE-113",
                            remediation="Tolak \\r\\n di parameter redirect. Pakai whitelist URL.",
                        ))
                        return findings
    finally:
        client.close()
    return findings
