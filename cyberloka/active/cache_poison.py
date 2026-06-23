"""Probe headers that are reflected but not part of cache key (poisoning hint)."""
from __future__ import annotations

import secrets

from cyberloka.core import Finding, HttpClient, Severity, Target
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
    return "public" in cc or "max-age" in cc or resp.headers.get("X-Cache") is not None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        baseline = client.get(target.base_url)
        if baseline is None or not _is_cacheable(baseline):
            return findings  # tidak ada cache yang bisa diracun
        for h in UNKEYED_HEADERS:
            marker = f"cyberloka-{secrets.token_hex(3)}.invalid"
            r = client.get(target.base_url, headers={h: marker})
            if r is None:
                continue
            body = r.text or ""
            if marker in body[:8000] or any(
                marker in v for v in r.headers.values()
            ):
                findings.append(Finding(
                    module="cache_poison",
                    title=f"Header `{h}` dipantulkan pada response yang cacheable",
                    severity=Severity.HIGH,
                    description=("Header non-standar dari klien dipantulkan ke response, "
                                 "sementara response bersifat cacheable. Berisiko cache "
                                 "poisoning: konten attacker ter-cache untuk korban lain."),
                    target=target.base_url,
                    evidence=f"{h}: {marker} → reflected; "
                             f"Cache-Control={r.headers.get('Cache-Control')}",
                    cwe="CWE-349",
                    remediation=("Tambahkan header tersebut ke cache key atau "
                                 "`Vary` header, atau matikan reflectionnya. "
                                 "Set `Cache-Control: private, no-store` untuk halaman yang "
                                 "memuat data per-user."),
                    references=[
                        "https://portswigger.net/research/practical-web-cache-poisoning"
                    ],
                ))
                break
    finally:
        client.close()
    return findings
