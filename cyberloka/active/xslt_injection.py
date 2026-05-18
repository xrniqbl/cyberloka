"""XSLT injection probe (rare but devastating)."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

XSL_PROBE = """<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text"/>
<xsl:template match="/">CYBERLOKA-XSLT-OK</xsl:template>
</xsl:stylesheet>"""


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    candidates = []
    if s:
        for u in s.urls:
            if any(k in u.lower() for k in ("xslt", "transform", "xml")):
                candidates.append(u)
    if not candidates:
        return findings
    client = HttpClient(config)
    try:
        for url in candidates[:3]:
            r = client.post(url, data=XSL_PROBE,
                            headers={"Content-Type": "application/xslt+xml"})
            if r is None:
                continue
            if "CYBERLOKA-XSLT-OK" in (r.text or ""):
                findings.append(Finding(
                    module="xslt_injection", target=url,
                    title="Endpoint mengevaluasi XSLT yang dikirim klien",
                    severity=Severity.CRITICAL,
                    description="Server processor XSLT dapat dimanipulasi attacker — sering RCE.",
                    evidence="XSLT marker reflected", cwe="CWE-91",
                    remediation="Jangan terima XSL stylesheet dari user. Pakai stylesheet hardcoded.",
                ))
                return findings
    finally:
        client.close()
    return findings
