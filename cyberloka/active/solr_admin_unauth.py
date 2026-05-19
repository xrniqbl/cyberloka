"""Apache Solr unauthenticated admin endpoint."""
from __future__ import annotations

import json
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = [
    "/solr/admin/cores?action=STATUS&wt=json",
    "/solr/admin/info/system?wt=json",
    "/solr/#/",
]


def _validate_solr(text: str, path: str) -> bool:
    head = text[:8192]
    if path.endswith("/"):
        return ("Solr Admin" in head or "AngularSolrAdmin" in head)
    try:
        data = json.loads(head)
    except (ValueError, TypeError):
        return False
    if not isinstance(data, dict):
        return False
    return ("responseHeader" in data and (
        "status" in data or "lucene" in data or "system" in data
    ))


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            if not _validate_solr(r.text or "", path):
                continue
            findings.append(Finding(
                module="solr_admin_unauth",
                title="Apache Solr admin terbuka tanpa autentikasi",
                severity=Severity.CRITICAL,
                description=(
                    "Endpoint admin Solr `/solr/admin/*` dapat diakses tanpa "
                    "autentikasi. Memberi attacker akses ke konfigurasi core, "
                    "kemampuan untuk mengaktifkan VelocityResponseWriter "
                    "yang berujung Remote Code Execution."
                ),
                target=url,
                urls=[url],
                evidence=f"GET {url} -> 200; struktur response Solr terkonfirmasi",
                cwe="CWE-306",
                confidence="confirmed",
                remediation=(
                    "Aktifkan Basic Authentication Plugin di Solr: tambah "
                    "`security.json` dengan credentials_provider. Pasang "
                    "Solr di belakang firewall + reverse-proxy basic-auth. "
                    "Disable `params.resource.loader.enabled` untuk mencegah "
                    "Velocity RCE."
                ),
                references=[
                    "https://solr.apache.org/guide/solr/latest/deployment-guide/authentication-and-authorization-plugins.html",
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-17558",
                ],
            ))
            break
    finally:
        client.close()
    return findings
