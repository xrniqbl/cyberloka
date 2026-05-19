"""Cache poisoning probe — strict-validation v0.10.4.

Sebelumnya: kalau marker dari header attacker dipantulkan ke response
yang cacheable, langsung flag. Banyak situs memantulkan header tetapi
response tidak benar-benar di-cache; ini menghasilkan FP.

Sekarang validasi dengan **cache replay**: setelah marker dipantulkan,
kirim request CLEAN (tanpa header attacker) ke URL yang sama. Hanya
laporkan kalau marker masih muncul di response clean — bukti bahwa
response ter-cache untuk klien lain.
"""
from __future__ import annotations

import secrets
import time

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
)
from cyberloka.core.config import ScanConfig

UNKEYED_HEADERS = (
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Host",
    "X-Forwarded-Server",
)


def _is_cacheable(resp) -> bool:
    cc = (resp.headers.get("Cache-Control", "") or "").lower()
    if "private" in cc or "no-store" in cc:
        return False
    return (
        "public" in cc or "max-age" in cc
        or resp.headers.get("X-Cache") is not None
        or resp.headers.get("CF-Cache-Status") is not None
        or resp.headers.get("Age") is not None
    )


def _marker_in_resp(resp, marker: str) -> bool:
    if marker in (resp.text or "")[:8000]:
        return True
    return any(marker in v for v in resp.headers.values())


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        baseline = client.get(target.base_url)
        if baseline is None or not _is_cacheable(baseline):
            return findings

        for h in UNKEYED_HEADERS:
            marker = f"cyberloka-{secrets.token_hex(4)}.invalid"
            r1 = client.get(target.base_url, headers={h: marker})
            if r1 is None or not _marker_in_resp(r1, marker):
                continue
            # Cache replay: kirim request CLEAN tanpa header attacker.
            time.sleep(0.5)
            r2 = client.get(target.base_url)
            if r2 is None or not _marker_in_resp(r2, marker):
                continue

            proof = ValidationProof(
                method="reflect+clean-replay",
                confirmed=True,
                steps=[
                    f"Request dengan header `{h}: {marker}` -> marker muncul di response.",
                    "Tunggu 0.5 detik, kirim request CLEAN tanpa header attacker.",
                    "Marker masih muncul di response clean -> response sudah ter-cache.",
                ],
                samples=[
                    f"poison: {h}: {marker}",
                    f"Cache-Control: {r1.headers.get('Cache-Control')}",
                ],
            )
            findings.append(Finding(
                module="cache_poison",
                title=f"Cache poisoning terkonfirmasi via header `{h}`",
                severity=Severity.HIGH,
                description=(
                    "Marker dari header non-standar dipantulkan ke response "
                    "DAN tetap muncul saat URL sama dipanggil ulang TANPA "
                    "header tersebut. Artinya cache shared menyimpan response "
                    "ter-poison untuk klien lain."
                ),
                target=target.base_url,
                evidence=f"{h}: {marker} -> reflected on poison + clean replay",
                cwe="CWE-349",
                confidence="confirmed",
                urls=[target.base_url],
                remediation=(
                    "Tambahkan header tersebut ke cache key atau `Vary` header, "
                    "atau matikan reflection-nya. Set "
                    "`Cache-Control: private, no-store` untuk halaman yang "
                    "memuat data per-user."
                ),
                references=[
                    "https://portswigger.net/research/practical-web-cache-poisoning",
                ],
                extra=build_extra(proof=proof),
            ))
            break
    finally:
        client.close()
    return findings
