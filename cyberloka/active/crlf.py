"""CRLF injection / HTTP response splitting detector.

Cek apakah server menyalurkan input user yang berisi CR/LF langsung ke
header response. Bila ya, attacker dapat menyuntikkan header tambahan
atau bahkan body palsu.
"""
from __future__ import annotations

from cyberloka.active._helpers import collect_target_urls, iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# %0d%0a = \r\n, %0a = \n. Beberapa server hanya rentan kalau pakai LF saja.
PAYLOADS = [
    "test%0d%0aSet-Cookie:%20cyberloka=injected",
    "test%0aSet-Cookie:%20cyberloka=injected",
    "test%E5%98%8A%E5%98%8DSet-Cookie:%20cyberloka=injected",  # unicode bypass
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    client = HttpClient(config)
    try:
        for url in collect_target_urls(target, default_param="redirect"):
            for payload in PAYLOADS:
                for param, mutated in iter_param_urls(url, payload):
                    key = f"{url.split('?')[0]}|{param}"
                    if key in seen:
                        continue
                    seen.add(key)
                    resp = client.get(mutated, allow_redirects=False)
                    if resp is None:
                        continue
                    # Kalau header response punya 'cyberloka', injection sukses
                    for hk, hv in resp.headers.items():
                        if "cyberloka" in str(hv).lower() or hk.lower() == "set-cookie" and "cyberloka=injected" in str(hv):
                            findings.append(
                                Finding(
                                    module="crlf",
                                    title=f"CRLF / Header injection pada parameter `{param}`",
                                    severity=Severity.HIGH,
                                    description=(
                                        "Server menyalurkan input user ke header response tanpa "
                                        "men-strip CR/LF. Attacker dapat menyuntikkan header "
                                        "(Set-Cookie palsu, Location ke domain attacker) atau bahkan "
                                        "body palsu (HTTP response splitting)."
                                    ),
                                    target=mutated,
                                    evidence=f"injected header: {hk}: {hv}",
                                    cwe="CWE-113",
                                    remediation=(
                                        "Strip karakter \\r dan \\n dari input sebelum di-set ke "
                                        "header. Gunakan API HTTP framework yang otomatis sanitize "
                                        "(modern Python urllib3/requests, Node http/2). Validasi "
                                        "URL untuk redirect."
                                    ),
                                    references=[
                                        "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
                                    ],
                                )
                            )
                            return findings
    finally:
        client.close()
    return findings
