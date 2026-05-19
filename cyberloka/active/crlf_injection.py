"""CRLF injection / HTTP response splitting probe."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

# Try multiple encodings of CRLF
PAYLOADS = [
    "%0d%0aSet-Cookie:cyberloka=injected",
    "%0d%0aX-Cyberloka:1",
    "\r\nX-Cyberloka:1",
    "%E5%98%8A%E5%98%8DSet-Cookie:cyberloka=injected",  # UTF-8 trick
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        urls = [target.base_url]
        s = get_state(config)
        if s:
            urls += s.param_urls[:5]
        seen: set[str] = set()
        for url in urls:
            parsed = urlparse(url)
            params = list(parse_qsl(parsed.query, keep_blank_values=True))
            if not params:
                continue
            k0 = params[0][0]
            if k0 in seen:
                continue
            seen.add(k0)
            for payload in PAYLOADS[:2]:
                new_params = [(k0, payload)] + params[1:]
                mutated = urlunparse(parsed._replace(query=urlencode(new_params, safe="%")))
                r = client.get(mutated, allow_redirects=False)
                if r is None:
                    continue
                # Cek apakah header injected muncul
                if (
                    "x-cyberloka" in {h.lower() for h in r.headers}
                    or "cyberloka=injected" in (r.headers.get("Set-Cookie", ""))
                ):
                    findings.append(Finding(
                        module="crlf_injection", target=mutated,
                        title=f"CRLF injection berhasil pada parameter `{k0}`",
                        severity=Severity.HIGH,
                        description=("Payload CRLF di parameter dipantulkan ke header response. "
                                     "Bisa dipakai untuk Set-Cookie attacker, cache poisoning, "
                                     "atau XSS lewat header."),
                        evidence=f"injected header observed in response",
                        cwe="CWE-93",
                        remediation=("Strip karakter CR (\\r) dan LF (\\n) dari semua input "
                                     "yang masuk ke header response. Validasi input dengan ketat."),
                    ))
                    return findings
    finally:
        client.close()
    return findings
