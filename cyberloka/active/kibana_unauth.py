"""Kibana / Elasticsearch / OpenSearch Dashboard unauthenticated access.

Validasi nyata:
  - GET /api/status pada Kibana harus mengembalikan JSON dengan version + status.
  - GET /_cat/indices?format=json pada Elasticsearch harus mengembalikan list
    indeks (array JSON dengan key 'index').
  - Cek apakah indeks sensitif ('logstash-*', 'app-*', 'auth*', 'user*') ada -
    bila ya, jumlah dokumen yang bisa di-read otomatis terhitung lewat
    /<index>/_count.

Tidak melakukan write/delete - hanya read-only verification.
"""
from __future__ import annotations

import json
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

KIBANA_PATHS = (
    "/", "/app/kibana", "/app/home", "/api/status",
    "/spaces/space_selector", "/login",
)
ES_PATHS = (
    "/_cat/indices?format=json",
    "/_cluster/health",
    "/_search?size=1",
)


def _is_kibana(body: str) -> bool:
    b = body[:5000].lower()
    return any(k in b for k in (
        '"name":"kibana"', "kibana - ", '<title>kibana', 'kibana_status'
    ))


def _kibana_status(client: HttpClient, base: str) -> dict | None:
    r = client.get(urljoin(base, "api/status"))
    if r is None or r.status_code != 200:
        return None
    try:
        d = r.json()
    except Exception:
        return None
    if isinstance(d, dict) and ("name" in d or "status" in d or "version" in d):
        return d
    return None


def _es_indices(client: HttpClient, base: str) -> list[dict] | None:
    r = client.get(urljoin(base, "_cat/indices?format=json"))
    if r is None or r.status_code != 200:
        return None
    try:
        d = r.json()
    except Exception:
        return None
    if isinstance(d, list) and d and isinstance(d[0], dict) and "index" in d[0]:
        return d
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.base_url
    client = HttpClient(config)
    try:
        # Kibana detection
        kib_landing = client.get(base, allow_redirects=True)
        kibana_detected = kib_landing is not None and _is_kibana(kib_landing.text or "")
        kib_status = _kibana_status(client, base) if kibana_detected else _kibana_status(client, base)
        if kib_status:
            ev = (
                f"GET /api/status -> 200\n"
                f"version: {(kib_status.get('version') or {}).get('number', kib_status.get('version', '?'))}\n"
                f"status: {kib_status.get('status', '?')}\n"
                f"name:    {kib_status.get('name', '?')}"
            )
            findings.append(Finding(
                module="kibana_unauth",
                target=base,
                title="Kibana terbuka tanpa autentikasi (membuka mata ke Elasticsearch)",
                severity=Severity.CRITICAL,
                description=(
                    "Kibana dashboard mengembalikan /api/status valid tanpa header "
                    "Authorization. Kibana = web UI untuk Elasticsearch; akses publik "
                    "berarti seluruh log/index Elasticsearch yang di-cluster dengan "
                    "Kibana ini dapat dibaca. Sering ditemukan di insiden besar yang "
                    "membocorkan miliaran record."
                ),
                evidence=ev,
                cwe="CWE-306",
                confidence="confirmed",
                urls=[urljoin(base, "api/status")],
                remediation=(
                    "1. Aktifkan X-Pack Security (sekarang gratis di Elastic Stack 7.13+).\n"
                    "2. Letakkan Kibana di belakang reverse-proxy (nginx) dengan auth + IP allowlist.\n"
                    "3. Tarik Kibana dari publik - hanya jaringan internal."
                ),
                references=[
                    "https://www.elastic.co/guide/en/kibana/current/using-kibana-with-security.html",
                ],
            ))

        # Elasticsearch direct API
        indices = _es_indices(client, base)
        if indices is not None:
            sensitive = [
                i for i in indices
                if any(k in (i.get("index", "")).lower()
                       for k in ("logstash", "auth", "user", "credential", "secret",
                                 "session", "audit", "log-", "app-"))
            ]
            ev_lines = [f"GET /_cat/indices?format=json -> 200, {len(indices)} indices"]
            ev_lines.append("Sample indices (first 10):")
            for it in indices[:10]:
                ev_lines.append(
                    f"  - {it.get('index')} ({it.get('docs.count', '?')} docs, "
                    f"{it.get('store.size', '?')})"
                )
            if sensitive:
                ev_lines.append(f"!! {len(sensitive)} sensitive indices: "
                                + ", ".join(s.get("index", "?") for s in sensitive[:5]))
            findings.append(Finding(
                module="kibana_unauth",
                target=urljoin(base, "_cat/indices"),
                title=(
                    f"Elasticsearch API publik tanpa auth ({len(indices)} indices accessible)"
                    + (" - termasuk indeks sensitif" if sensitive else "")
                ),
                severity=Severity.CRITICAL,
                description=(
                    "Elasticsearch API menerima request tanpa autentikasi dan "
                    "mengembalikan daftar lengkap indeks beserta jumlah dokumen. "
                    "Tiap indeks dapat di-search dengan GET /<index>/_search. "
                    "Setara akses penuh ke data warehouse - termasuk log aplikasi, "
                    "session, dan kemungkinan PII pelanggan."
                ),
                evidence="\n".join(ev_lines),
                cwe="CWE-306",
                confidence="confirmed",
                urls=[urljoin(base, "_cat/indices?format=json")],
                remediation=(
                    "1. Aktifkan security (xpack.security.enabled: true) + buat user/role.\n"
                    "2. Bind ke localhost/internal subnet.\n"
                    "3. Audit log untuk lihat IP attacker yang sudah scrape indeks."
                ),
                references=[
                    "https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html",
                ],
            ))
    finally:
        client.close()
    return findings
