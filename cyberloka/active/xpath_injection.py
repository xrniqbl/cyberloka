"""XPath injection probe."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

PAYLOADS = ["' or '1'='1", "'] | //user/* | //a[", "*"]
ERROR_HINT = ("xpath", "xml parser", "xpathexception", "system.xml.xpath")


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings
    client = HttpClient(config)
    try:
        for url in s.param_urls[:5]:
            for payload in PAYLOADS:
                r = client.get(url, params={"q": payload})
                if r is None:
                    continue
                body = (r.text or "").lower()
                if any(e in body for e in ERROR_HINT):
                    findings.append(Finding(
                        module="xpath_injection", target=url,
                        title="XPath error terekspos",
                        severity=Severity.HIGH,
                        description="Server membongkar error XPath saat input dimanipulasi.",
                        evidence=f"payload={payload}", cwe="CWE-643",
                        remediation="Pakai parametrik XPath (XQuery prepared) atau pindah ke JSON.",
                    ))
                    return findings
    finally:
        client.close()
    return findings
