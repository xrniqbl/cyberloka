"""Detect Server-Timing header that leaks internal timings."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url)
        if r is None:
            return findings
        st = r.headers.get("Server-Timing")
        if st:
            findings.append(Finding(
                module="server_timing_header", target=target.base_url,
                title="Server-Timing header membocorkan timing internal",
                severity=Severity.LOW,
                description=("Header `Server-Timing` mengekspos durasi DB/cache/render server. "
                             "Membantu attacker melakukan timing attack atau memetakan arsitektur."),
                evidence=f"Server-Timing: {st[:200]}",
                cwe="CWE-200",
                remediation=("Hapus header `Server-Timing` di production. Tampilkan hanya untuk "
                             "developer/admin yang authenticated."),
            ))
    finally:
        client.close()
    return findings
