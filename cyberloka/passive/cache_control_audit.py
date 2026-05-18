"""Audit Cache-Control on sensitive pages."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

SENSITIVE_RE = re.compile(
    r"(account|profile|order|invoice|cart|checkout|saldo|wallet|"
    r"dashboard|admin|user|setting|payment)",
    re.I,
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    s = get_state(config)
    if not s:
        return findings
    candidates = [u for u in s.urls if SENSITIVE_RE.search(u)][:8]
    if not candidates:
        return findings
    try:
        bad: list[tuple[str, str, str]] = []
        for url in candidates:
            r = client.get(url)
            if r is None:
                continue
            cc = (r.headers.get("Cache-Control") or "").lower()
            pragma = (r.headers.get("Pragma") or "").lower()
            # Halaman sensitif harus: no-store atau private + no-cache
            problem = None
            if not cc:
                problem = "Cache-Control header tidak ada"
            elif "public" in cc and "private" not in cc:
                problem = "Cache-Control: public — bisa dikache CDN/proxy"
            elif "no-store" not in cc and "no-cache" not in cc and "private" not in cc:
                problem = f"Cache-Control: {cc} — tidak ada larangan cache"
            if problem:
                bad.append((url, cc or "(none)", problem))
        if bad:
            findings.append(Finding(
                module="cache_control_audit", target=target.base_url,
                title=f"{len(bad)} halaman sensitif tanpa Cache-Control yang aman",
                severity=Severity.MEDIUM,
                description=("Halaman yang memuat data per-user (akun, order, saldo) sebaiknya "
                             "TIDAK boleh ter-cache di CDN/Cloudflare. Kalau ter-cache, user lain "
                             "bisa melihat data orang lain dari cache."),
                evidence="\n".join(f"{u}: {p}" for u, _, p in bad[:8]),
                cwe="CWE-525",
                remediation=("Set `Cache-Control: no-store, private` di response halaman "
                             "sensitif. Untuk Cloudflare, exclude path tersebut dari cache rule."),
            ))
    finally:
        client.close()
    return findings
