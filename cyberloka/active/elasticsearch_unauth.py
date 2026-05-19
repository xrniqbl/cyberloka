"""Elasticsearch unauthenticated cluster exposure.

Auto-validation: probe / dan /_cluster/health, validasi via JSON struktur
khas Elasticsearch (`cluster_name`, `version`, `tagline`).
"""
from __future__ import annotations

import json
from urllib.parse import urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = ["/", "/_cluster/health", "/_cat/indices?format=json", "/_cat/health?format=json"]
CANDIDATE_PORTS = [9200, 9201]


def _candidates(target: Target) -> list[str]:
    parsed = urlparse(target.origin)
    host = parsed.hostname or target.host
    out: list[str] = [target.origin.rstrip("/")]
    for p in CANDIDATE_PORTS:
        for scheme in ("http", "https"):
            out.append(urlunparse((scheme, f"{host}:{p}", "/", "", "", "")).rstrip("/"))
    seen, dedup = set(), []
    for u in out:
        if u not in seen:
            seen.add(u)
            dedup.append(u)
    return dedup


def _validate(text: str) -> dict | None:
    try:
        d = json.loads(text)
    except (ValueError, TypeError):
        return None
    if isinstance(d, dict):
        if "cluster_name" in d or d.get("tagline", "").lower().startswith(
                "you know, for search"):
            return d
        if "name" in d and "version" in d and isinstance(d["version"], dict) \
                and "number" in d["version"]:
            return d
    if isinstance(d, list) and d and isinstance(d[0], dict) \
            and "index" in d[0] and "health" in d[0]:
        return {"_indices": d}
    return None


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
                data = _validate((r.text or "")[:8192])
                if not data:
                    continue
                version = (data.get("version") or {}).get("number") if isinstance(
                    data.get("version"), dict) else data.get("version")
                cluster = data.get("cluster_name") or data.get("name") or "?"
                findings.append(Finding(
                    module="elasticsearch_unauth",
                    title=f"Elasticsearch tanpa autentikasi: {base}",
                    severity=Severity.CRITICAL,
                    description=(
                        "Cluster Elasticsearch dapat di-query tanpa autentikasi. "
                        f"Cluster `{cluster}` versi `{version}`. Index "
                        "biasanya berisi log produksi / PII."
                    ),
                    target=url,
                    urls=[url],
                    evidence=f"GET {url} -> 200; cluster={cluster}; version={version}",
                    cwe="CWE-306",
                    confidence="confirmed",
                    remediation=(
                        "Aktifkan Elastic Stack security: `xpack.security.enabled=true`. "
                        "Setup user/role di Kibana atau via API setup-passwords. "
                        "Bind ke localhost: `network.host: 127.0.0.1`. Pasang "
                        "reverse-proxy (Nginx) basic-auth di depan."
                    ),
                    references=[
                        "https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html",
                    ],
                ))
                seen = True
                break
    finally:
        client.close()
    return findings
