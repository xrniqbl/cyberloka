"""GraphQL DoS probe (depth, alias bombing)."""
from __future__ import annotations

import time
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

ENDPOINTS = ("/graphql", "/api/graphql", "/v1/graphql", "/query")

DEEP_QUERY = "query{" + "user{user{user{user{user{user{user{user{user{id}}}}}}}}}" + "}"
ALIAS_BOMB = "query{" + " ".join(f"a{i}:__schema{{queryType{{name}}}}" for i in range(50)) + "}"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in ENDPOINTS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.post(url, json={"query": "{__typename}"})
            if r is None or r.status_code >= 400:
                continue
            if "data" not in (r.text or "") and "errors" not in (r.text or ""):
                continue

            # Test 1: deep nested query
            t0 = time.monotonic()
            r1 = client.post(url, json={"query": DEEP_QUERY})
            dt1 = time.monotonic() - t0
            if r1 is not None and r1.status_code in (200, 400):
                body = (r1.text or "").lower()
                if "exceed" not in body and "too deep" not in body and "depth" not in body:
                    findings.append(Finding(
                        module="graphql_dos", target=url,
                        title="GraphQL endpoint tidak membatasi query depth",
                        severity=Severity.MEDIUM,
                        description=("Query nested 9-level diterima tanpa penolakan. "
                                     "Attacker dapat craft query dengan ribuan nested "
                                     "untuk DoS database."),
                        evidence=f"depth-9 query accepted in {dt1:.2f}s",
                        cwe="CWE-770",
                        remediation=("Pasang query-depth limit (mis. graphql-depth-limit), "
                                     "biasanya max 7-10 level."),
                    ))

            # Test 2: alias bombing
            t0 = time.monotonic()
            r2 = client.post(url, json={"query": ALIAS_BOMB})
            dt2 = time.monotonic() - t0
            if r2 is not None and r2.status_code == 200 and dt2 < 5.0:
                body = (r2.text or "").lower()
                if "rate" not in body and "too many" not in body:
                    findings.append(Finding(
                        module="graphql_dos", target=url,
                        title="GraphQL menerima 50 alias dalam satu query",
                        severity=Severity.MEDIUM,
                        description=("Alias bombing: 50 query introspection dijalankan dalam "
                                     "satu request HTTP. Attacker bisa scaling ke ribuan alias "
                                     "untuk amplifikasi load."),
                        evidence=f"50 aliases accepted in {dt2:.2f}s",
                        cwe="CWE-770",
                        remediation=("Pasang cost-analysis (graphql-cost-analysis) atau "
                                     "limit alias per request (max 5-10)."),
                    ))
            return findings
    finally:
        client.close()
    return findings
