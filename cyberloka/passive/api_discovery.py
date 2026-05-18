"""API surface discovery: Swagger/OpenAPI/Actuator/well-known."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

API_PATHS: list[tuple[str, str, Severity]] = [
    # path, label, severity if found
    ("/swagger-ui.html", "Swagger UI", Severity.MEDIUM),
    ("/swagger/index.html", "Swagger UI", Severity.MEDIUM),
    ("/swagger-ui/index.html", "Swagger UI", Severity.MEDIUM),
    ("/swagger.json", "Swagger spec", Severity.MEDIUM),
    ("/v2/api-docs", "Swagger v2 docs", Severity.MEDIUM),
    ("/v3/api-docs", "Swagger v3 docs", Severity.MEDIUM),
    ("/openapi.json", "OpenAPI spec", Severity.MEDIUM),
    ("/openapi.yaml", "OpenAPI spec", Severity.MEDIUM),
    ("/api-docs", "API docs", Severity.LOW),
    ("/docs", "API docs", Severity.INFO),
    ("/redoc", "ReDoc", Severity.LOW),
    ("/graphql", "GraphQL endpoint", Severity.INFO),
    ("/graphiql", "GraphiQL UI", Severity.HIGH),
    ("/playground", "GraphQL Playground", Severity.HIGH),
    ("/altair", "GraphQL Altair", Severity.HIGH),
    # Spring Boot Actuator
    ("/actuator", "Spring Boot Actuator", Severity.HIGH),
    ("/actuator/health", "Actuator /health", Severity.LOW),
    ("/actuator/env", "Actuator /env (env vars)", Severity.CRITICAL),
    ("/actuator/heapdump", "Actuator /heapdump", Severity.CRITICAL),
    ("/actuator/mappings", "Actuator /mappings", Severity.MEDIUM),
    ("/actuator/loggers", "Actuator /loggers", Severity.MEDIUM),
    ("/actuator/beans", "Actuator /beans", Severity.MEDIUM),
    ("/actuator/threaddump", "Actuator /threaddump", Severity.MEDIUM),
    # Common API roots
    ("/api", "Generic /api root", Severity.INFO),
    ("/api/v1", "/api/v1 root", Severity.INFO),
    ("/api/v2", "/api/v2 root", Severity.INFO),
    ("/api/v3", "/api/v3 root", Severity.INFO),
    # well-known
    ("/.well-known/security.txt", "security.txt", Severity.INFO),
    ("/.well-known/openid-configuration", "OIDC discovery", Severity.INFO),
    ("/.well-known/oauth-authorization-server", "OAuth metadata", Severity.INFO),
    # k8s/cloud probes
    ("/metrics", "Prometheus /metrics", Severity.MEDIUM),
    ("/debug/pprof/", "Go pprof debug", Severity.HIGH),
    ("/debug/vars", "Go expvar", Severity.MEDIUM),
    # Misc consoles
    ("/manager/html", "Tomcat Manager", Severity.HIGH),
    ("/host-manager/html", "Tomcat Host Manager", Severity.HIGH),
    ("/jolokia", "Jolokia JMX", Severity.HIGH),
    ("/console", "JBoss/Glassfish console", Severity.HIGH),
    ("/h2-console", "H2 DB console", Severity.HIGH),
]


def _check(client: HttpClient, base: str, path: str, label: str, sev: Severity):
    url = urljoin(base, path)
    resp = client.get(url, allow_redirects=False)
    if resp is None:
        return None
    if resp.status_code in (200, 201) and resp.content:
        body = resp.text or ""
        # filter false positives where SPA returns 200 for everything
        body_l = body.lower()
        if path == "/api" and "<html" in body_l and "swagger" not in body_l and "openapi" not in body_l:
            return None
        return url, label, sev, resp.status_code, truncate(body, 240)
    if resp.status_code in (401, 403) and "actuator" in path:
        # auth-protected actuator is still notable but lower
        return url, label + " (auth required)", Severity.LOW, resp.status_code, ""
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    base = target.origin + "/"
    try:
        with ThreadPoolExecutor(max_workers=min(20, config.threads * 2)) as ex:
            futures = [ex.submit(_check, client, base, p, lbl, sev) for p, lbl, sev in API_PATHS]
            for fut in as_completed(futures):
                res = fut.result()
                if not res:
                    continue
                url, label, sev, status, ev = res
                findings.append(
                    Finding(
                        module="api_discovery",
                        title=f"{label} ter-ekspos: {url}",
                        severity=sev,
                        description=(
                            "Endpoint API/dokumentasi/console terdeteksi terbuka di internet. "
                            "Untuk perusahaan besar, dokumentasi & management console "
                            "harus dilindungi (private network / VPN / auth) karena "
                            "mengungkap struktur API & potensi RCE (Actuator/H2/Jolokia)."
                        ),
                        target=url,
                        evidence=f"HTTP {status}\n{ev}",
                        remediation=(
                            "Batasi akses ke endpoint dokumentasi/management hanya untuk "
                            "internal network atau di belakang otentikasi. Untuk Spring Boot "
                            "Actuator: set `management.endpoints.web.exposure.include=health` "
                            "saja, atau pakai `management.server.port` terpisah. Hapus "
                            "console (H2, Tomcat manager) di environment produksi."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                            "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
                        ],
                    )
                )
    finally:
        client.close()
    return findings
