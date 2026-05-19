"""API version downgrade auth-bypass detection.

Auto-validation: untuk endpoint sensitif yang ditemukan crawler, coba
prefix versi lama (/api/v0, /api/v1, /api/old, /api/legacy) tanpa
Authorization. Bila response 200 + struktur JSON serupa = legacy auth
bypass.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

API_RE = re.compile(r"^/api/(v\d+|v\d+\.\d+|latest|current)/", re.I)
# Endpoint sensitif yang lazim tersedia di banyak versi
SENSITIVE_HINTS = re.compile(r"/(users?|profile|me|account|orders?|admin|"
                             r"transactions?|payments?|invoices?|secret)", re.I)
# Versi alternatif yang dicoba
ALT_VERSIONS = ["v0", "v1", "old", "legacy", "internal", "beta", "preview"]


def _candidates_from_state(state) -> list[str]:
    paths: set[str] = set()
    for u in (state.urls if state else []):
        p = urlparse(u).path
        if API_RE.search(p) and SENSITIVE_HINTS.search(p):
            paths.add(p)
    return sorted(paths)


def _alt_paths(path: str) -> list[str]:
    out = []
    m = API_RE.search(path)
    if not m:
        return out
    for alt in ALT_VERSIONS:
        out.append(path.replace(m.group(1), alt, 1))
    return out


def _looks_like_data(text: str) -> bool:
    head = text[:8192].strip()
    if not head:
        return False
    try:
        d = json.loads(head)
    except (ValueError, TypeError):
        return False
    return isinstance(d, (list, dict)) and bool(d)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    state = get_state(config)
    base = _candidates_from_state(state)
    if not base:
        return findings
    client = HttpClient(config)
    try:
        for path in base[:6]:
            # Baseline: minta endpoint asli tanpa auth -> harusnya 401
            base_url = urljoin(target.origin + "/", path.lstrip("/"))
            cur = client.get(base_url, allow_redirects=False)
            if cur is None:
                continue
            cur_status = cur.status_code
            # Hanya menarik kalau current version memang mewajibkan auth
            if cur_status not in (401, 403):
                continue

            for alt in _alt_paths(path):
                alt_url = urljoin(target.origin + "/", alt.lstrip("/"))
                r = client.get(alt_url, allow_redirects=False)
                if r is None or r.status_code != 200:
                    continue
                if not _looks_like_data(r.text or ""):
                    continue
                findings.append(Finding(
                    module="api_version_downgrade",
                    title=f"Bypass auth via API versi lama: {alt}",
                    severity=Severity.HIGH,
                    description=(
                        f"Endpoint terkini `{path}` mewajibkan auth "
                        f"(HTTP {cur_status}), namun versi lama `{alt}` "
                        "balas 200 + data. Versi API lama belum ditutup / "
                        "memakai middleware autentikasi yang lebih lemah."
                    ),
                    target=alt_url,
                    urls=[base_url, alt_url],
                    evidence=(
                        f"GET {base_url} -> {cur_status}; "
                        f"GET {alt_url} -> {r.status_code} (data JSON)"
                    ),
                    cwe="CWE-287",
                    confidence="confirmed",
                    remediation=(
                        "Matikan endpoint API versi lama atau pasang "
                        "middleware autentikasi yang sama dengan versi "
                        "terkini. Tambahkan deprecation header, lalu "
                        "redirect ke versi baru. Audit semua route yang "
                        "match `/api/v[0-9]+/` di production."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                    ],
                ))
                break
            if len(findings) >= 2:
                break
    finally:
        client.close()
    return findings
