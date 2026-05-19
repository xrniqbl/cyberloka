"""Prometheus / Spring Actuator / Node.js metrics endpoint leak validator.

Memvalidasi bukan sekadar 'metrics endpoint terbuka', tapi juga:
  - Apakah memuat secret pattern (Bearer token, jdbc URL, AWS key, dll.)
  - Apakah Actuator /env atau /heapdump bisa di-download (heapdump = sangat
    kritikal, biasanya berisi password plaintext).

Hanya mengeluarkan finding kalau benar-benar ada signal aktif.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

ENDPOINTS = (
    ("/metrics", "prometheus", Severity.MEDIUM),
    ("/actuator/metrics", "actuator-metrics", Severity.MEDIUM),
    ("/actuator/prometheus", "actuator-prometheus", Severity.MEDIUM),
    ("/actuator/env", "actuator-env", Severity.HIGH),
    ("/actuator/health", "actuator-health", Severity.LOW),
    ("/actuator/heapdump", "actuator-heapdump", Severity.CRITICAL),
    ("/actuator/loggers", "actuator-loggers", Severity.LOW),
    ("/actuator/mappings", "actuator-mappings", Severity.MEDIUM),
    ("/actuator/configprops", "actuator-configprops", Severity.HIGH),
    ("/actuator/beans", "actuator-beans", Severity.MEDIUM),
    ("/actuator", "actuator-index", Severity.MEDIUM),
    ("/debug/vars", "expvar", Severity.MEDIUM),
    ("/debug/pprof/", "go-pprof", Severity.HIGH),
    ("/-/metrics", "haproxy-metrics", Severity.MEDIUM),
    ("/admin/metrics", "admin-metrics", Severity.MEDIUM),
    ("/api/v1/query", "prometheus-api", Severity.MEDIUM),
)

SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "Google API key"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI / private key"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "GitHub token"),
    (re.compile(r"jdbc:[a-z]+://[^\s\"']+"), "JDBC URL"),
    (re.compile(r"mongodb(?:\+srv)?://[^\s\"']+"), "MongoDB URI"),
    (re.compile(r"postgres(?:ql)?://[^\s\"']+"), "Postgres URI"),
    (re.compile(r"mysql://[^\s\"']+"), "MySQL URI"),
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"), "Private key"),
    (re.compile(r"\"password\"\s*:\s*\"[^\"]{4,}\""), "JSON password field"),
    (re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9._-]+"), "Bearer token in body"),
]


def _scan_secrets(body: str) -> list[str]:
    found: list[str] = []
    for pat, label in SECRET_PATTERNS:
        m = pat.search(body)
        if m:
            sample = m.group(0)
            sample = sample[:60] + ("..." if len(sample) > 60 else "")
            found.append(f"{label}: {sample}")
    return found


def _is_real_metrics(body: str, label: str) -> bool:
    b = (body or "").strip()
    if not b:
        return False
    if "prometheus" in label or "metrics" in label:
        # Format Prometheus: # HELP ... atau # TYPE ... atau metric_name{...} value
        if "# HELP" in b or "# TYPE" in b or re.search(r"^[a-z_]+\{.*\}\s+[\d.eE+-]+", b, re.M):
            return True
    if label == "actuator-env" and ("propertySources" in b or "activeProfiles" in b):
        return True
    if label == "actuator-heapdump" and (
        b.startswith("PK") or b.startswith("\x1f\x8b") or "HeapDump" in b
    ):
        return True
    if label == "actuator-index" and ('"_links"' in b or '"links"' in b):
        return True
    if label == "actuator-mappings" and "dispatcherServlets" in b:
        return True
    if label == "actuator-configprops" and '"contexts"' in b:
        return True
    if label == "actuator-loggers" and '"loggers"' in b:
        return True
    if label == "expvar" and ('"cmdline"' in b or '"memstats"' in b):
        return True
    if label == "go-pprof" and ("/debug/pprof/" in b or b.startswith("Types of profiles")):
        return True
    return False


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.base_url
    client = HttpClient(config)
    try:
        for path, label, sev in ENDPOINTS:
            url = urljoin(base, path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            if not _is_real_metrics(body, label):
                continue
            secrets = _scan_secrets(body)
            real_sev = Severity.CRITICAL if secrets else sev
            evidence_parts = [f"URL: {url}", f"Status: {r.status_code}", f"Type: {label}"]
            if label == "actuator-heapdump":
                evidence_parts.append(f"Body length: {len(body)} bytes (binary heapdump)")
            else:
                snippet = body[:300].replace("\n", " ")
                evidence_parts.append(f"Body snippet: {snippet}")
            if secrets:
                evidence_parts.append("SECRETS DETECTED:\n" + "\n".join(f"  - {s}" for s in secrets))

            title = f"Metrics/Actuator endpoint terbuka: {label}"
            if secrets:
                title += f" (BERISI {len(secrets)} secret pattern)"
            elif label == "actuator-heapdump":
                title = "Spring Actuator heapdump dapat di-download (kredensial plaintext)"

            findings.append(Finding(
                module="prometheus_metrics_leak",
                target=url,
                title=title,
                severity=real_sev,
                description=(
                    "Endpoint metrics / monitoring / debug terbuka publik dan "
                    "merespons dengan format yang valid (bukan halaman default). "
                    + (
                        "DI DALAM body terdeteksi pola kredensial nyata (lihat evidence). "
                        "Ini membuat finding ini = pelanggaran data aktif, bukan teoretis. "
                        if secrets else
                        "Endpoint ini biasanya membocorkan internal name resource, version "
                        "library, dan path konfigurasi yang sangat berguna untuk attacker. "
                    )
                    + (
                        "Heapdump berisi snapshot memory aplikasi - termasuk semua password "
                        "dan token yang sedang dipakai. Setara dengan kunci master."
                        if label == "actuator-heapdump" else ""
                    )
                ),
                evidence="\n".join(evidence_parts),
                cwe="CWE-200" if not secrets else "CWE-798",
                confidence="confirmed",
                urls=[url],
                remediation=(
                    "Spring Boot Actuator: di application.properties, set "
                    "`management.endpoints.web.exposure.include=health,info` saja - "
                    "matikan env, heapdump, configprops, loggers di production. "
                    "Prometheus /metrics: lindungi dengan IP allowlist atau basic auth. "
                    "Go pprof: hanya expose di internal listener (mis. localhost:6060)."
                ),
                references=[
                    "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
                    "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
                ],
            ))
    finally:
        client.close()
    return findings
