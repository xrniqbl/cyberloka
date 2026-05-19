"""Prometheus unauthenticated metrics endpoint."""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = ["/metrics", "/api/v1/targets", "/api/v1/query?query=up"]
CANDIDATE_PORTS = [9090, 9091, 9100]


def _candidates(target: Target) -> list[str]:
    parsed = urlparse(target.origin)
    host = parsed.hostname or target.host
    out = [target.origin.rstrip("/")]
    for p in CANDIDATE_PORTS:
        for scheme in ("http", "https"):
            out.append(urlunparse((scheme, f"{host}:{p}", "/", "", "", "")).rstrip("/"))
    seen, dedup = set(), []
    for u in out:
        if u not in seen:
            seen.add(u)
            dedup.append(u)
    return dedup


def _is_prometheus(text: str, headers: dict) -> bool:
    head = text[:8192]
    # Prometheus /metrics format: HELP/TYPE comments
    if "# HELP" in head and "# TYPE" in head:
        return True
    # /api/v1/* JSON style
    if '"status":"success"' in head and ('"data"' in head):
        ct = (headers.get("Content-Type") or "").lower()
        if "json" in ct:
            return True
    return False


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    seen = False
    try:
        for base in _candidates(target):
            if seen:
                break
            for path in PATHS:
                url = base.rstrip("/") + path
                r = client.get(url, allow_redirects=False)
                if r is None or r.status_code != 200:
                    continue
                if not _is_prometheus(r.text or "", dict(r.headers)):
                    continue
                findings.append(Finding(
                    module="prometheus_unauth",
                    title=f"Prometheus terbuka tanpa autentikasi: {url}",
                    severity=Severity.HIGH,
                    description=(
                        "Endpoint Prometheus `/metrics` atau `/api/v1/*` "
                        "dapat diakses tanpa autentikasi. Ungkap blueprint "
                        "service internal, hostname, versi software."
                    ),
                    target=url,
                    urls=[url],
                    evidence=f"GET {url} -> 200; format Prometheus terdeteksi",
                    cwe="CWE-200",
                    confidence="confirmed",
                    remediation=(
                        "Pasang basic-auth di reverse-proxy (nginx) di depan "
                        "Prometheus. Bind Prometheus ke localhost: "
                        "`--web.listen-address=127.0.0.1:9090`. Pakai TLS "
                        "client cert untuk scrape antar-host."
                    ),
                    references=[
                        "https://prometheus.io/docs/operating/security/",
                    ],
                ))
                seen = True
                break
    finally:
        client.close()
    return findings
