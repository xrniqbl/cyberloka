"""Client-Side Template Injection (AngularJS / Vue) detection.

Auto-validation: kirim `{{7*7}}` atau `{{7*8}}` ke parameter URL; cek
apakah body memuat hasil evaluasi (`49` / `56`) tanpa kurung kurawal,
atau pola khas AngularJS sandbox eval.
"""
from __future__ import annotations

import re

from cyberloka.active._helpers import (
    append_param,
    candidate_urls,
    iter_param_urls,
)
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.validation import random_arith_pair

NEG_RE = re.compile(r"\{\{[^}]*\}\}")  # body harusnya BUKAN memantulkan literal {{...}}
ANGULAR_HINT = re.compile(r"(ng-app|ng-controller|angular\.js|window\.angular)", re.I)


def _build_payloads() -> list[tuple[str, str]]:
    """Oracle aritmetika ACAK (bukan 7*7) agar marker tidak muncul kebetulan.

    Produk dua bilangan 113..9973 selalu 4-7 digit dan nyaris mustahil
    muncul secara incidental di halaman (item count, harga, dsb.).
    """
    a, b, prod = random_arith_pair()
    e = str(prod)
    return [
        (f"{{{{{a}*{b}}}}}", e),   # AngularJS / Vue / Liquid
        (f"[[{a}*{b}]]", e),       # custom interpolator
        (f"${{{a}*{b}}}", e),      # FreeMarker / Vue style
    ]


def _scan_url(client, url, is_angular_like, baseline_body):
    findings: list[Finding] = []
    for payload, expected in _build_payloads():
        # Guard: kalau marker sudah ada di baseline, oracle tidak valid.
        if expected in (baseline_body or "")[:65536]:
            continue
        for param, mutated in iter_param_urls(url, payload):
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
    return findings


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    seen_paths: set[str] = set()
    try:
        from urllib.parse import urlparse
        # Konfirmasi apakah target memakai AngularJS (untuk severity).
        homepage = client.get(target.base_url)
        if homepage is None:
            return findings
        baseline_body = homepage.text or ""
        is_angular_like = bool(ANGULAR_HINT.search(baseline_body))

        for url in candidate_urls(target, config, fallback_param="q", fallback_value="cyblok"):
            path = urlparse(url).path
            if path in seen_paths:
                continue
            for f in _scan_url(client, url, is_angular_like, baseline_body):
                seen_paths.add(path)
                findings.append(f)
    finally:
        client.close()
    return findings
