"""XPath injection probe — strict-validation v0.10.4.

Sebelumnya: kalau body memuat keyword ``xpath``/``xml parser``, flag.
Banyak halaman dokumentasi atau dashboard memuat kata "xpath" sehingga
banyak FP.

Sekarang flag HANYA bila signature error XPath spesifik muncul setelah
payload disuntik DAN baseline (request bersih) tidak memuat signature
yang sama.
"""
from __future__ import annotations

import secrets

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

PAYLOADS = ["' or '1'='1", "'] | //user/* | //a[", "*"]
ERROR_HINT = (
    "xpathexception",
    "system.xml.xpath",
    "xpath syntax error",
    "javax.xml.xpath.xpathexpressionexception",
    "xpath: //",
    "expected token",
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings
    client = HttpClient(config)
    try:
        for url in s.param_urls[:5]:
            base_value = f"cyberloka_baseline_{secrets.token_hex(3)}"
            base = client.get(url, params={"q": base_value})
            base_low = (base.text or "").lower() if base is not None else ""
            if any(e in base_low for e in ERROR_HINT):
                continue
            for payload in PAYLOADS:
                r = client.get(url, params={"q": payload})
                if r is None:
                    continue
                body = (r.text or "").lower()
                triggered = [e for e in ERROR_HINT if e in body]
                if not triggered:
                    continue
                proof = ValidationProof(
                    method="error-leak+baseline-clean",
                    confirmed=True,
                    steps=[
                        f"Baseline `q={base_value}` -> tidak ada signature XPath.",
                        f"Probe `q={payload}` -> signature: {triggered[:3]}.",
                    ],
                    samples=[f"payload={payload}, signatures={triggered[:3]}"],
                )
                findings.append(Finding(
                    module="xpath_injection", target=url,
                    title="XPath error terkonfirmasi (baseline clean)",
                    severity=Severity.HIGH,
                    description=(
                        "Server membongkar signature error XPath setelah input "
                        "dimanipulasi, sementara baseline bersih tidak memuat "
                        "signature tersebut."
                    ),
                    evidence=f"payload={payload}; signatures={triggered[:3]}",
                    cwe="CWE-643",
                    confidence="confirmed",
                    urls=[url],
                    remediation=(
                        "Pakai parametrik XPath (XQuery prepared) atau pindah ke JSON."
                    ),
                    extra=build_extra(proof=proof),
                ))
                return findings
    finally:
        client.close()
    return findings
