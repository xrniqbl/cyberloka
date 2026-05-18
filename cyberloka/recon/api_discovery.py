"""Probe well-known API surface paths."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

API_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/v2/api-docs",
    "/api/swagger.json",
    "/graphql",
    "/graphiql",
    "/playground",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/api/",
    "/api/v1/",
    "/api/v2/",
]

GRAPHQL_INTROSPECTION = {
    "query": "{__schema { types { name } } }"
}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    base = target.origin
    try:
        for path in API_PATHS:
            url = base + path
            r = client.get(url)
            if r is None or r.status_code >= 400:
                continue
            ctype = r.headers.get("Content-Type", "")
            sev = Severity.INFO
            title = f"API surface terbuka: {path}"
            desc = (
                "Endpoint API dokumentasi/discovery dapat diakses publik. "
                "Surface ini biasanya dipakai attacker untuk memetakan endpoint."
            )
            cwe = "CWE-200"
            if path in ("/swagger.json", "/openapi.json", "/swagger/v1/swagger.json"):
                if "json" in ctype:
                    sev = Severity.MEDIUM
                    title = f"OpenAPI/Swagger spec terbuka: {path}"
            if path in ("/graphql", "/graphiql"):
                # try introspection
                ri = client.post(url, json=GRAPHQL_INTROSPECTION)
                if ri is not None and "__schema" in (ri.text or ""):
                    sev = Severity.HIGH
                    title = "GraphQL introspection aktif"
                    desc = "Introspection mengizinkan siapa pun mendapatkan skema lengkap GraphQL."
                    cwe = "CWE-200"
            findings.append(
                Finding(
                    module="api_discovery",
                    title=title,
                    severity=sev,
                    description=desc,
                    target=url,
                    evidence=f"HTTP {r.status_code} · Content-Type: {ctype}",
                    cwe=cwe,
                    remediation=(
                        "Batasi akses ke dokumentasi API (auth/IP allowlist), nonaktifkan "
                        "GraphQL introspection di produksi, dan hapus endpoint dev yang tidak terpakai."
                    ),
                )
            )
    finally:
        client.close()
    return findings
