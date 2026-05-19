"""Web Cache Deception detection.

Auto-validation: butuh session login (config.cookies / login_*). Akses
endpoint privat normal dan endpoint privat + ".css". Bila response .css
berisi konten privat yang sama AND header cache mengindikasikan cached
(`age:`, `cf-cache-status: HIT`, `x-cache: HIT`) -> vulnerable.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PRIVATE_PATHS = [
    "/profile", "/me", "/account", "/dashboard", "/settings",
    "/api/me", "/api/profile", "/api/users/me",
    "/user/profile", "/my-account",
]
CACHE_HEADERS = ("age", "cf-cache-status", "x-cache", "x-served-by",
                 "x-vercel-cache", "x-cache-hits")
PII_HINTS = re.compile(r"\b(email|username|user_id|phone|nik|alamat|address|"
                       r"first_?name|last_?name)\b", re.I)


def _has_cache_hit(headers: dict) -> str | None:
    for k, v in headers.items():
        kl = k.lower()
        if kl in CACHE_HEADERS:
            sv = (v or "").lower()
            if "hit" in sv or kl == "age" and sv.isdigit() and int(sv) > 0:
                return f"{k}: {v}"
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    # Hanya jalan bila ada session (cookies / bearer / login result)
    has_auth = bool(config.cookies or config.auth_bearer_token
                    or config.login_username)
    if not has_auth:
        return findings

    client = HttpClient(config)
    try:
        for p in PRIVATE_PATHS:
            url = urljoin(target.origin + "/", p.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            if not PII_HINTS.search(body[:8192]):
                continue
            # Probe cache deception: tambahkan /cyblok.css
            mutated = url.rstrip("/") + "/cyblok-poc.css"
            r2 = client.get(mutated, allow_redirects=False)
            if r2 is None:
                continue
            if r2.status_code != 200:
                continue
            # Konten harus mirip (PII tetap muncul)
            if not PII_HINTS.search((r2.text or "")[:8192]):
                continue
            cache_evidence = _has_cache_hit(dict(r2.headers))
            if not cache_evidence:
                # Periksa juga indikasi cacheable: Cache-Control: public/max-age
                cc = (r2.headers.get("Cache-Control") or "").lower()
                if not ("public" in cc or "max-age" in cc and "no-store" not in cc):
                    continue
                cache_evidence = f"Cache-Control: {cc}"
            findings.append(Finding(
                module="cache_deception",
                title=f"Web Cache Deception pada {urlparse(url).path}",
                severity=Severity.HIGH,
                description=(
                    "Endpoint privat `{p}` mengembalikan data PII walau "
                    "URL ditambah ekstensi `.css`. CDN/cache memperlakukan "
                    "response sebagai static -> attacker dapat memanen data "
                    "privat user lain dari cache yang sama."
                ).format(p=urlparse(url).path),
                target=mutated,
                urls=[url, mutated],
                evidence=(
                    f"GET {url} -> 200 PII; "
                    f"GET {mutated} -> 200 PII; "
                    f"cache_indicator: {cache_evidence}"
                ),
                cwe="CWE-525",
                confidence="confirmed",
                remediation=(
                    "Konfigurasi cache di edge: jangan cache response yang "
                    "menetapkan Set-Cookie atau body yang berasal dari path "
                    "dynamic. Pasang `Cache-Control: private, no-store` pada "
                    "endpoint authenticated. Cocokkan static path lewat "
                    "regex (`^/static/`), bukan ekstensi semata."
                ),
                references=[
                    "https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html",
                ],
            ))
            if len(findings) >= 2:
                break
    finally:
        client.close()
    return findings
