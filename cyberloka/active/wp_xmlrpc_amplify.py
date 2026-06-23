"""WordPress xmlrpc.php amplification & brute-force detection.

Auto-validation: POST `system.listMethods` ke /xmlrpc.php dan validasi XML
response berisi `pingback.ping` atau `wp.getUsersBlogs`.
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

XMLRPC_BODY = (
    '<?xml version="1.0"?>'
    '<methodCall><methodName>system.listMethods</methodName>'
    '<params></params></methodCall>'
)
PATHS = ["/xmlrpc.php", "/wp/xmlrpc.php", "/blog/xmlrpc.php"]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.post(url, data=XMLRPC_BODY,
                            headers={"Content-Type": "text/xml"},
                            allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            if "<methodResponse>" not in body or "<value>" not in body:
                continue
            has_pingback = "pingback.ping" in body
            has_brute = "wp.getUsersBlogs" in body or "system.multicall" in body
            if not (has_pingback or has_brute):
                continue
            risks = []
            if has_pingback:
                risks.append("pingback.ping (DDoS amplification & SSRF)")
            if has_brute:
                risks.append("wp.getUsersBlogs / system.multicall (1000x brute per req)")
            findings.append(Finding(
                module="wp_xmlrpc_amplify",
                title="WordPress xmlrpc.php aktif & rentan amplifikasi/brute",
                severity=Severity.HIGH,
                description=(
                    "Endpoint xmlrpc.php WordPress aktif dengan method "
                    "berbahaya: " + ", ".join(risks) + "."
                ),
                target=url,
                urls=[url],
                evidence=f"POST {url} body=system.listMethods -> XML response valid",
                cwe="CWE-770",
                confidence="confirmed",
                remediation=(
                    "Bila tidak butuh xmlrpc.php, blok di reverse-proxy "
                    "(`location = /xmlrpc.php { return 403; }`). Bila perlu "
                    "(Jetpack), batasi via plugin Disable XML-RPC Pingback "
                    "dan IP allowlist. Pasang fail2ban untuk POST ke xmlrpc.php."
                ),
                references=[
                    "https://make.wordpress.org/core/handbook/best-practices/post-development/",
                    "https://www.wordfence.com/blog/2014/03/wordpress-pingback-ddos-attacks/",
                ],
            ))
            break
    finally:
        client.close()
    return findings
