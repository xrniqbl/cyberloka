"""XXE probe: send XML body with safe out-of-band marker."""
from __future__ import annotations

import secrets
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

XML_PROBE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent-{marker}">]>
<root><test>&xxe;</test></root>"""


def _xml_endpoints(target: Target, config: ScanConfig) -> list[str]:
    out = set()
    state = get_state(config)
    if state:
        for u in state.urls:
            if any(s in u.lower() for s in ("xml", "soap", "wsdl", "import", "feed")):
                out.add(u)
    for path in ("/api/xml", "/soap", "/api/import", "/sitemap.xml"):
        out.add(urljoin(target.origin + "/", path))
    return list(out)[:5]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for url in _xml_endpoints(target, config):
            marker = secrets.token_hex(4)
            payload = XML_PROBE.format(marker=marker)
            r = client.post(
                url,
                data=payload,
                headers={"Content-Type": "application/xml"},
            )
            if r is None:
                continue
            body = r.text or ""
            indicators = ("nonexistent-" + marker, "no such file or directory",
                          "failed to load external entity", "DOCTYPE is not allowed")
            if any(s in body for s in indicators):
                findings.append(Finding(
                    module="xxe",
                    title=f"Endpoint memproses external entity XML: {url}",
                    severity=Severity.HIGH,
                    description=("Server memproses entity XXE dan respons memuat hint dari "
                                 "parser XML. Berpotensi pembacaan file lokal & SSRF."),
                    target=url, evidence=body[:300],
                    cwe="CWE-611",
                    remediation=("Matikan resolusi external entity di parser XML. "
                                 "Di Python: `defusedxml`, di Java: "
                                 "`XMLConstants.FEATURE_SECURE_PROCESSING`."),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
                    ],
                ))
                break
    finally:
        client.close()
    return findings
