"""Burst test: send a small concurrent burst to see if WAF/rate-limiter responds.

Bukan DoS — kami sengaja membatasi jumlah dan durasi.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

BURST_REQUESTS = 30
BURST_WORKERS = 10


def _hit(client: HttpClient, url: str) -> int:
    r = client.get(url, allow_redirects=False)
    return r.status_code if r is not None else 0


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    # disable rate limit for burst, but cap requests strictly.
    burst_cfg = ScanConfig(**{**config.__dict__, "rate_limit": 0})
    client = HttpClient(burst_cfg)
    try:
        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=BURST_WORKERS) as ex:
            statuses = list(
                ex.map(lambda _: _hit(client, target.base_url), range(BURST_REQUESTS))
            )
        elapsed = time.monotonic() - start
        ratelimited = sum(1 for s in statuses if s in (429, 503, 403))
        ev = (
            f"requests={len(statuses)} elapsed={elapsed:.2f}s "
            f"ratelimited={ratelimited} statuses={statuses}"
        )
        if ratelimited == 0:
            findings.append(
                Finding(
                    module="burst",
                    title="Tidak ada respons rate-limit pada burst test",
                    severity=Severity.LOW,
                    description=(
                        f"{BURST_REQUESTS} request paralel tidak satupun direspon 429/503/403. "
                        "Pertimbangkan menambahkan rate limiting / WAF di edge."
                    ),
                    target=target.base_url,
                    evidence=ev,
                    remediation=(
                        "Aktifkan rate-limit per IP / per ASN di reverse-proxy (Nginx "
                        "limit_req), CDN/WAF (Cloudflare, AWS WAF, dsb.) untuk mencegah "
                        "scraping, brute-force, dan abuse."
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    module="burst",
                    title="Rate-limit aktif (burst test)",
                    severity=Severity.INFO,
                    description=f"{ratelimited}/{BURST_REQUESTS} request kena rate-limit.",
                    target=target.base_url,
                    evidence=ev,
                )
            )
    finally:
        client.close()
    return findings
