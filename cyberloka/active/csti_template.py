"""Client-Side Template Injection (AngularJS / Vue) detection.

Auto-validation: kirim `{{7*7}}` atau `{{7*8}}` ke parameter URL; cek
apakah body memuat hasil evaluasi (`49` / `56`) tanpa kurung kurawal,
atau pola khas AngularJS sandbox eval.
"""
from __future__ import annotations

import re

from cyberloka.active._helpers import append_param, iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# (payload, expected_marker_in_body)
PAYLOADS = [
    ("{{7*7}}", "49"),
    ("{{8*8}}", "64"),
    ("[[7*7]]", "49"),     # custom interpolator
    ("${7*7}", "49"),      # FreeMarker / Vue style
]
NEG_RE = re.compile(r"\{\{[^}]*\}\}")  # body harusnya BUKAN memantulkan literal {{...}}
ANGULAR_HINT = re.compile(r"(ng-app|ng-controller|angular\.js|window\.angular)", re.I)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        url = target.base_url
        # Konfirmasi target memakai AngularJS dulu (untuk reduce false-positive)
        homepage = client.get(url)
        if homepage is None:
            return findings
        is_angular_like = bool(ANGULAR_HINT.search(homepage.text or ""))

        # Bila tidak ada parameter, tambahkan param test
        test_url = url
        if "?" not in test_url:
            test_url = append_param(test_url, "q", "cyblok")

        for payload, expected in PAYLOADS:
            for param, mutated in iter_param_urls(test_url, payload):
                r = client.get(mutated)
                if r is None:
                    continue
                body = r.text or ""
                # Cari hasil evaluasi DAN payload literal TIDAK ada
                # (kalau payload literal masih ada, berarti tidak dievaluasi).
                if expected in body[:65536] and payload not in body[:65536]:
                    sev = Severity.HIGH if is_angular_like else Severity.MEDIUM
                    findings.append(Finding(
                        module="csti_template",
                        title=f"Client-side Template Injection di parameter `{param}`",
                        severity=sev,
                        description=(
                            "Payload `{{7*7}}` (atau varian) dievaluasi di "
                            "client-side template (AngularJS / Vue / "
                            "FreeMarker). Hasil eksekusi `49` muncul di body "
                            "sementara literal `{{...}}` tidak dipantulkan. "
                            "AngularJS sandbox eval dapat naik ke XSS yang "
                            "lolos CSP standar."
                        ),
                        target=mutated,
                        urls=[mutated],
                        evidence=(
                            f"payload={payload}; body memuat `{expected}` "
                            f"tanpa literal payload"
                        ),
                        cwe="CWE-1336",
                        confidence="confirmed",
                        remediation=(
                            "Hindari interpolasi data user di template "
                            "client-side. Untuk AngularJS, jangan render "
                            "input mentah dengan `ng-bind-html` tanpa "
                            "$sce.trustAsHtml + sanitasi. Migrasi dari "
                            "AngularJS (sudah EOL Jan 2022) ke Angular "
                            "modern. Pasang CSP `script-src 'self'` strict."
                        ),
                        references=[
                            "https://portswigger.net/research/server-side-template-injection",
                            "https://owasp.org/www-project-cheat-sheets/cheatsheets/AngularJS_Security_Cheat_Sheet.html",
                        ],
                    ))
                    return findings
    finally:
        client.close()
    return findings
