"""GraphQL endpoint detection + introspection check."""
from __future__ import annotations

import json
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/query"]
INTROSPECTION_QUERY = {
    "query": "{__schema{types{name}}}"
}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in GRAPHQL_PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            # GET with query param to detect endpoint
            probe = client.get(url + "?query={__typename}", allow_redirects=False)
            looks_like_gql = False
            evidence = ""
            if probe is not None and probe.status_code in (200, 400, 405):
                ctype = probe.headers.get("Content-Type", "").lower()
                body = probe.text or ""
                if "application/json" in ctype and ("__typename" in body or "errors" in body or "data" in body):
                    looks_like_gql = True
                    evidence = body[:240]
            if not looks_like_gql:
                continue

            findings.append(
                Finding(
                    module="graphql",
                    title=f"GraphQL endpoint terdeteksi: {url}",
                    severity=Severity.INFO,
                    description="Endpoint GraphQL ditemukan.",
                    target=url,
                    evidence=evidence,
                    remediation=(
                        "Pastikan endpoint GraphQL menerapkan otentikasi & otorisasi "
                        "per-resolver, query depth/complexity limiting, serta rate limiting."
                    ),
                )
            )

            # Try introspection
            r = client.post(
                url,
                json=INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
                allow_redirects=False,
            )
            if r is None:
                continue
            try:
                data = r.json() if r.content else {}
            except (ValueError, json.JSONDecodeError):
                data = {}
            if isinstance(data, dict) and data.get("data", {}).get("__schema"):
                types = data["data"]["__schema"].get("types", [])
                findings.append(
                    Finding(
                        module="graphql",
                        title=f"GraphQL introspection terbuka: {url}",
                        severity=Severity.HIGH,
                        description=(
                            "Introspection mengizinkan attacker mengunduh seluruh schema "
                            "(types, fields, mutations, args). Di production environment, "
                            "ini membocorkan permukaan serangan internal."
                        ),
                        target=url,
                        evidence=f"Jumlah types: {len(types)}",
                        cwe="CWE-200",
                        remediation=(
                            "Nonaktifkan introspection di production (Apollo: "
                            "`introspection: false`; GraphQL Java: disable IntrospectionQuery; "
                            "Hasura: disable via env). Whitelist persisted queries jika perlu."
                        ),
                        references=[
                            "https://owasp.org/www-project-graphql-cheat-sheet/",
                        ],
                    )
                )
    finally:
        client.close()
    return findings
