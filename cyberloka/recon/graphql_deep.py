"""Deeper GraphQL inspection: introspection, alias batching surface."""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

ENDPOINTS = ("/graphql", "/api/graphql", "/v1/graphql", "/query")
INTROSPECTION = {"query": "{__schema { types { name fields { name } } } }"}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in ENDPOINTS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.post(url, json=INTROSPECTION)
            if r is None or r.status_code >= 400:
                continue
            body = r.text or ""
            if "__schema" not in body:
                continue
            findings.append(Finding(
                module="graphql_deep",
                title=f"GraphQL introspection aktif di {path}",
                severity=Severity.MEDIUM,
                description=("Introspection mengizinkan siapa pun mengunduh skema GraphQL "
                             "lengkap (semua type, field, query, mutation) — peta sempurna "
                             "untuk attacker."),
                target=url,
                evidence=f"len={len(body)} bytes mengandung __schema",
                cwe="CWE-200",
                remediation=("Matikan introspection di production (mis. di Apollo Server: "
                             "`introspection: false`). Tambahkan auth + cost-analysis untuk "
                             "mencegah query batching DoS."),
            ))
            # Suggestion-based field enumeration: query yang typo
            r2 = client.post(url, json={"query": "{ Userr { id } }"})
            if r2 is not None:
                msg = (r2.text or "").lower()
                if "did you mean" in msg:
                    findings.append(Finding(
                        module="graphql_deep",
                        title="GraphQL field-suggestion aktif (membantu enumerasi)",
                        severity=Severity.LOW,
                        description=("Pesan error 'Did you mean...' bocorkan nama field yang "
                                     "valid — mempermudah attacker memetakan skema bahkan "
                                     "ketika introspection dimatikan."),
                        target=url, evidence=msg[:200], cwe="CWE-200",
                        remediation="Matikan suggestion engine di production GraphQL server.",
                    ))
            break
    finally:
        client.close()
    return findings
