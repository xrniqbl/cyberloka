"""API pagination & data dump abuse detector.

Cek apakah endpoint list-API mengizinkan limit/page-size yang sangat besar
sehingga attacker bisa men-dump seluruh dataset dalam beberapa request.
"""
from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

LIMIT_PARAMS = ("limit", "size", "per_page", "page_size", "perpage", "count", "max")


def _swap_param(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    out = []
    found = False
    for k, v in pairs:
        if k.lower() == key.lower():
            out.append((k, value))
            found = True
        else:
            out.append((k, v))
    if not found:
        out.append((key, value))
    return urlunparse(p._replace(query=urlencode(out, doseq=True)))


def _is_listing(body: str) -> bool:
    """Heuristic: body is a JSON array atau object yang punya key 'data'/'items'/'results'."""
    try:
        d = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return False
    if isinstance(d, list) and len(d) >= 5:
        return True
    if isinstance(d, dict):
        for k in ("data", "items", "results", "rows", "records", "list"):
            if k in d and isinstance(d[k], list):
                return True
    return False


def _count_items(body: str) -> int:
    try:
        d = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return 0
    if isinstance(d, list):
        return len(d)
    if isinstance(d, dict):
        for k in ("data", "items", "results", "rows", "records", "list"):
            v = d.get(k)
            if isinstance(v, list):
                return len(v)
    return 0


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    discovered = getattr(target, "discovered", None)
    if discovered is None:
        return findings

    candidates: list[str] = []
    for ep in getattr(discovered, "endpoints", []):
        if ep.method.upper() != "GET":
            continue
        # endpoint API JSON yang berpotensi listing
        low = ep.url.lower()
        if "/api/" in low or low.endswith(".json"):
            candidates.append(ep.url)
    candidates = list(dict.fromkeys(candidates))[:15]

    if not candidates:
        return findings

    client = HttpClient(config)
    try:
        for url in candidates:
            # Baseline
            base = client.get(url)
            if base is None or "json" not in base.headers.get("Content-Type", "").lower():
                continue
            base_body = base.text or ""
            if not _is_listing(base_body):
                continue
            base_count = _count_items(base_body)

            # Probe limit huge
            for param in LIMIT_PARAMS:
                if f"{param}=" not in url.lower() and not url.endswith(".json"):
                    # tambahkan param jika belum ada
                    pass
                test_url = _swap_param(url, param, "100000")
                resp = client.get(test_url)
                if resp is None:
                    continue
                test_body = resp.text or ""
                test_count = _count_items(test_body)
                if test_count > base_count * 5 and test_count >= 50:
                    findings.append(
                        Finding(
                            module="api_pagination",
                            title=f"API pagination tidak di-cap di {url}",
                            severity=Severity.HIGH,
                            description=(
                                f"Endpoint mengembalikan {test_count} item ketika "
                                f"`{param}=100000` dipakai (baseline {base_count} item). "
                                "Attacker dapat men-dump seluruh dataset dalam 1 request "
                                "(scraping, kompetitor intel, abuse rate-limit per-request)."
                            ),
                            target=test_url,
                            evidence=(
                                f"baseline_count={base_count} @ {url}\n"
                                f"large_request_count={test_count} @ ?{param}=100000"
                            ),
                            cwe="CWE-770",
                            remediation=(
                                "Cap maximum page size di server-side (mis. max=100). "
                                "Reject atau silently cap parameter `limit` yang berlebihan. "
                                "Pertimbangkan cursor-based pagination untuk dataset besar."
                            ),
                            references=[
                                "https://owasp.org/www-project-api-security/2023/en/0xa4-unrestricted-resource-consumption.html",
                            ],
                        )
                    )
                    break
    finally:
        client.close()
    return findings
