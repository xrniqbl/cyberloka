"""API authentication & data-exposure checks.

For each API-shaped URL discovered by the crawler, perform three checks:
1. Missing-auth: if user provided auth (cookie/bearer), retry without auth
   and see whether the API still returns the same data.
2. Mass data export: GET endpoints that return arrays should ideally be
   paginated. We flag responses with very large arrays.
3. Rate-limit: send a small burst of requests and check if any 429 appears.
"""
from __future__ import annotations

import json
import re
import time

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

API_HINT = re.compile(r"/api/|/v\d+/|/graphql|/rest/", re.I)


def _api_urls(config: ScanConfig) -> list[str]:
    state = get_state(config)
    if not state:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for u in state.urls + state.param_urls:
        if API_HINT.search(u) and u not in seen:
            seen.add(u)
            out.append(u)
    return out[:10]


def _looks_like_data(body: str, ctype: str) -> bool:
    if "json" in ctype.lower():
        return True
    return body.strip().startswith(("{", "["))


def _check_missing_auth(client: HttpClient, config: ScanConfig,
                       urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    has_auth = bool(config.cookies) or bool(config.auth_bearer_token) \
        or any(k.lower() == "authorization" for k in config.headers)
    if not has_auth:
        # User tidak menyediakan auth — kami tidak bisa membandingkan with vs without.
        return findings
    # Build an unauthenticated client clone
    no_auth_cfg = ScanConfig(
        target=config.target, mode=config.mode, threads=1,
        timeout=config.timeout, rate_limit=config.rate_limit,
        verify_tls=config.verify_tls, user_agent=config.user_agent,
    )
    plain_client = HttpClient(no_auth_cfg)
    try:
        for url in urls[:5]:
            r_auth = client.get(url)
            r_plain = plain_client.get(url)
            if r_auth is None or r_plain is None:
                continue
            ctype = r_auth.headers.get("Content-Type", "")
            body_auth = r_auth.text or ""
            body_plain = r_plain.text or ""
            if not _looks_like_data(body_auth, ctype):
                continue
            # Heuristic: tanpa auth tetap dapat data 2xx + len mirip
            if (r_plain.status_code in (200, 201) and
                    abs(len(body_plain) - len(body_auth)) < max(50, len(body_auth) * 0.2) and
                    _looks_like_data(body_plain, ctype)):
                findings.append(Finding(
                    module="api_auth",
                    title=f"API mengembalikan data tanpa autentikasi: {url}",
                    severity=Severity.HIGH,
                    description=(
                        "Endpoint API merespons dengan data yang sangat mirip "
                        "antara request dengan auth dan tanpa auth. Indikasi "
                        "endpoint tidak memvalidasi autentikasi/otorisasi."
                    ),
                    target=url,
                    evidence=f"with-auth status={r_auth.status_code}, "
                             f"len={len(body_auth)}; without-auth status="
                             f"{r_plain.status_code}, len={len(body_plain)}",
                    cwe="CWE-306",
                    remediation=(
                        "Wajibkan autentikasi (middleware) di semua endpoint API. "
                        "Pakai @login_required / authentication middleware, "
                        "jangan bergantung pada front-end menyembunyikan endpoint."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                    ],
                ))
                if len(findings) >= 2:
                    break
    finally:
        plain_client.close()
    return findings


def _check_mass_export(client: HttpClient, urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for url in urls[:5]:
        r = client.get(url)
        if r is None:
            continue
        ctype = r.headers.get("Content-Type", "")
        body = r.text or ""
        if "json" not in ctype.lower():
            continue
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            continue
        # Cek array ukuran besar
        items = None
        if isinstance(parsed, list):
            items = parsed
        elif isinstance(parsed, dict):
            for k in ("data", "items", "results", "users", "products", "orders"):
                v = parsed.get(k)
                if isinstance(v, list):
                    items = v
                    break
        if items is None:
            continue
        if len(items) >= 100:
            findings.append(Finding(
                module="api_auth",
                title=f"API mengembalikan {len(items)} item tanpa pagination",
                severity=Severity.MEDIUM,
                description=(
                    "Endpoint listing mengembalikan jumlah item sangat besar "
                    "dalam satu response. Jika tidak ada batas atas pagination, "
                    "attacker dapat menarik seluruh database lewat satu request."
                ),
                target=url,
                evidence=f"items_count={len(items)}",
                cwe="CWE-770",
                remediation=(
                    "Batasi `limit` maksimum (mis. 100), wajibkan parameter "
                    "`page`/`cursor`. Tambahkan rate-limit + audit log untuk "
                    "endpoint listing."
                ),
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                ],
            ))
            if len(findings) >= 2:
                break
    return findings


def _check_rate_limit(client: HttpClient, urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    if not urls:
        return findings
    url = urls[0]
    statuses: list[int] = []
    t0 = time.monotonic()
    for _ in range(20):
        r = client.get(url)
        if r is None:
            break
        statuses.append(r.status_code)
        if r.status_code == 429:
            break
    elapsed = time.monotonic() - t0
    if statuses and 429 not in statuses and elapsed < 4.0:
        findings.append(Finding(
            module="api_auth",
            title="Endpoint API tidak memiliki rate-limit yang terdeteksi",
            severity=Severity.LOW,
            description=(
                "20 request berturut-turut ke endpoint API tidak memunculkan "
                "respons 429 (Too Many Requests). Tanpa rate-limit, API rentan "
                "scraping massal dan brute-force."
            ),
            target=url,
            evidence=f"sent=20, 429_seen=False, elapsed={elapsed:.2f}s",
            cwe="CWE-770",
            remediation=(
                "Pasang rate-limit per-IP dan per-akun (mis. 60 req/menit), "
                "kembalikan 429 dengan header `Retry-After`."
            ),
        ))
    return findings


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    urls = _api_urls(config)
    if not urls:
        return findings
    client = HttpClient(config)
    try:
        findings.extend(_check_missing_auth(client, config, urls))
        findings.extend(_check_mass_export(client, urls))
        findings.extend(_check_rate_limit(client, urls))
    finally:
        client.close()
    return findings
