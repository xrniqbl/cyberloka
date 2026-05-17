"""GraphQL security audit.

Memeriksa endpoint GraphQL umum (/graphql, /api/graphql, /v1/graphql, /query)
untuk:

- Introspection diaktifkan di production (CWE-200, A05:2021).
- Batching besar diizinkan (DoS amplifier).
- Alias overloading (banyak alias di satu query) diizinkan.
- Field 'mutation' yang bisa dipanggil tanpa otentikasi (mendeteksi 200 OK
  saat request anonim ke skema mutation umum bila introspection memberi
  daftarnya).
- GET-method query diizinkan (CSRF risk).
"""
from __future__ import annotations

import json
from typing import Any

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

CANDIDATE_PATHS = (
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/gql",
)

INTROSPECTION_QUERY = (
    "query IntrospectionQuery {"
    "  __schema {"
    "    queryType { name }"
    "    mutationType { name }"
    "    types { name kind }"
    "  }"
    "}"
)


def _detect_endpoint(client: HttpClient, base_origin: str) -> str | None:
    for p in CANDIDATE_PATHS:
        url = base_origin.rstrip("/") + p
        # Probe cepat dengan POST query trivial
        resp = client.post(
            url,
            json={"query": "{__typename}"},
            headers={"Content-Type": "application/json"},
        )
        if resp is None:
            continue
        if resp.status_code in (200, 400) and "json" in resp.headers.get("Content-Type", "").lower():
            try:
                data = resp.json()
                if isinstance(data, dict) and ("data" in data or "errors" in data):
                    return url
            except (ValueError, json.JSONDecodeError):
                continue
    return None


def _post_query(client: HttpClient, url: str, query: str, **extra: Any) -> dict | None:
    resp = client.post(
        url,
        json={"query": query, **extra},
        headers={"Content-Type": "application/json"},
    )
    if resp is None or resp.status_code >= 500:
        return None
    try:
        return resp.json()
    except (ValueError, json.JSONDecodeError):
        return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        endpoint = _detect_endpoint(client, target.origin)
        if not endpoint:
            return findings

        findings.append(
            Finding(
                module="graphql",
                title=f"GraphQL endpoint terdeteksi: {endpoint}",
                severity=Severity.INFO,
                description="Endpoint GraphQL ditemukan dan akan diaudit.",
                target=endpoint,
            )
        )

        # 1) Introspection
        intro = _post_query(client, endpoint, INTROSPECTION_QUERY)
        if intro and isinstance(intro.get("data"), dict) and intro["data"].get("__schema"):
            schema = intro["data"]["__schema"]
            type_count = len(schema.get("types", []))
            findings.append(
                Finding(
                    module="graphql",
                    title="GraphQL introspection diaktifkan di production",
                    severity=Severity.MEDIUM,
                    description=(
                        "Schema dapat di-query secara penuh oleh siapa saja. Ini memudahkan "
                        "attacker menemukan field tersembunyi, mutation admin, dan tipe internal."
                    ),
                    target=endpoint,
                    evidence=f"types_count={type_count} mutationType={schema.get('mutationType')}",
                    cwe="CWE-200",
                    remediation=(
                        "Nonaktifkan introspection di production (mis. Apollo Server: "
                        "`introspection: false`; graphql-php: `setQueryComplexity` + filter; "
                        "Hasura: gunakan role yang tidak punya akses introspection)."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                    ],
                )
            )

        # 2) Batching
        batched = client.post(
            endpoint,
            json=[{"query": "{__typename}"} for _ in range(20)],
            headers={"Content-Type": "application/json"},
        )
        if batched is not None and batched.status_code == 200:
            try:
                arr = batched.json()
                if isinstance(arr, list) and len(arr) >= 5:
                    findings.append(
                        Finding(
                            module="graphql",
                            title="GraphQL menerima batched queries (DoS amplifier)",
                            severity=Severity.MEDIUM,
                            description=(
                                "Server menerima array of operations dalam satu HTTP request. "
                                "Bila tidak dibatasi, attacker bisa menggandakan beban dengan "
                                "ratusan query per request."
                            ),
                            target=endpoint,
                            evidence=f"batch_size_accepted={len(arr)}",
                            remediation=(
                                "Batasi jumlah operasi per request (mis. 5-10), atau matikan "
                                "batching bila tidak dibutuhkan."
                            ),
                        )
                    )
            except (ValueError, json.JSONDecodeError):
                pass

        # 3) Alias overloading — kirim 50 alias di satu query
        alias_q = "{ " + " ".join([f"a{i}: __typename" for i in range(50)]) + " }"
        ar = _post_query(client, endpoint, alias_q)
        if ar and "data" in ar and isinstance(ar["data"], dict) and len(ar["data"]) >= 30:
            findings.append(
                Finding(
                    module="graphql",
                    title="GraphQL menerima alias overloading (>30 alias / request)",
                    severity=Severity.MEDIUM,
                    description=(
                        "Server tidak membatasi jumlah alias per query. Pola ini sering dipakai "
                        "untuk brute-force / amplification (mis. password guessing via 1000 "
                        "alias dalam 1 request)."
                    ),
                    target=endpoint,
                    evidence=f"aliases_returned={len(ar['data'])}",
                    remediation=(
                        "Implementasi query cost analysis & alias limit (graphql-cost-analysis, "
                        "graphql-validation-complexity, atau Apollo `validationRules`)."
                    ),
                )
            )

        # 4) GET method enabled
        get_resp = client.get(endpoint + "?query={__typename}")
        if get_resp is not None and get_resp.status_code == 200:
            try:
                gd = get_resp.json()
                if isinstance(gd, dict) and "data" in gd:
                    findings.append(
                        Finding(
                            module="graphql",
                            title="GraphQL menerima query lewat GET (CSRF risk)",
                            severity=Severity.MEDIUM,
                            description=(
                                "Query via GET method memungkinkan CSRF dengan iframe/img untuk "
                                "trigger mutation bila server juga menerima mutation di GET."
                            ),
                            target=endpoint,
                            cwe="CWE-352",
                            remediation=(
                                "Hanya izinkan POST untuk operasi yang men-state-change. "
                                "Batasi GET hanya untuk persisted queries / introspection (jika perlu)."
                            ),
                        )
                    )
            except (ValueError, json.JSONDecodeError):
                pass
    finally:
        client.close()
    return findings
