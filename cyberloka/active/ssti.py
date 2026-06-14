"""Server-Side Template Injection probe."""
from __future__ import annotations

from cyberloka.active._helpers import append_param, candidate_urls, iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PROBES = [
    ("{{7*7}}", "49"),    # Jinja2 / Twig
    ("${{7*7}}", "49"),   # Velocity / Spring
    ("<%= 7*7 %>", "49"), # ERB
    ("#{7*7}", "49"),     # Ruby/Pug
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        probes = [
            (scan_url, payload, expected)
            for scan_url in candidate_urls(target, config, "q", "test")
            for payload, expected in PROBES
        ]
        for scan_url, payload, expected in probes:
            for param, mutated in iter_param_urls(scan_url, payload):
                r = client.get(mutated)
                if r is None:
                    continue
                body = r.text or ""
                if expected in body and payload not in body:
                    findings.append(
                        Finding(
                            module="ssti",
                            title=f"Server-Side Template Injection pada `{param}`",
                            severity=Severity.CRITICAL,
                            confidence="confirmed",
                            description=(
                                f"Payload template `{payload}` dievaluasi server-side menjadi "
                                f"`{expected}`. SSTI dapat berujung RCE."
                            ),
                            target=mutated,
                            evidence=f"payload={payload!r} → output mengandung '{expected}'",
                            cwe="CWE-94",
                            remediation=(
                                "Jangan render input user lewat template engine. Gunakan engine "
                                "auto-escape, jalankan template di sandbox, dan filter karakter "
                                "kontrol template."
                            ),
                        )
                    )
                    return findings
    finally:
        client.close()
    return findings
