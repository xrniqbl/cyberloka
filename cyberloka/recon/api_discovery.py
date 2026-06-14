"""Probe well-known API surface paths — verification-first.

Modul lama melaporkan path apa pun yang balik status < 400 (mis. `/api/`,
`/graphiql`, `/playground`) sebagai temuan, padahal SPA mengembalikan index.html
200 untuk semuanya. Kini setiap path harus BUKAN catch-all dan lolos validator
konten (spec JSON yang valid, UI GraphQL nyata, atau introspection yang benar aktif).
"""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core import probe

# path -> validator(ctype, body) yang membuktikan ini benar surface API, bukan SPA.
SPEC_PATHS = {
    "/swagger.json": lambda c, b: probe.is_json_doc(c, b) and ("swagger" in b.lower() or "openapi" in b.lower()),
    "/swagger/v1/swagger.json": lambda c, b: probe.is_json_doc(c, b),
    "/openapi.json": lambda c, b: probe.is_json_doc(c, b) and "openapi" in b.lower(),
    "/openapi.yaml": lambda c, b: ("openapi" in b.lower() or "swagger" in b.lower()) and not probe.looks_like_html(b),
    "/api-docs": lambda c, b: probe.is_json_doc(c, b),
    "/v2/api-docs": lambda c, b: probe.is_json_doc(c, b),
    "/api/swagger.json": lambda c, b: probe.is_json_doc(c, b),
}
WELLKNOWN_PATHS = {
    "/.well-known/security.txt": lambda c, b: ("contact:" in b.lower() or "policy:" in b.lower()) and not probe.looks_like_html(b),
    "/.well-known/openid-configuration": lambda c, b: probe.is_json_doc(c, b) and "issuer" in b.lower(),
}
GRAPHQL_PATHS = ["/graphql", "/graphiql", "/playground"]
GRAPHQL_INTROSPECTION = {"query": "{__schema { types { name } } }"}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    base = target.origin
    try:
        for path, validator in {**SPEC_PATHS, **WELLKNOWN_PATHS}.items():
            r = probe.verify_real(client, target, base + path, validator=validator)
            if r is None:
                continue
            ctype = r.headers.get("Content-Type", "")
            is_spec = path in SPEC_PATHS
            findings.append(Finding(
                module="api_discovery",
                title=(f"OpenAPI/Swagger spec terbuka: {path}" if is_spec
                       else f"API surface terbuka: {path}"),
                severity=Severity.MEDIUM if is_spec else Severity.LOW,
                description=("Endpoint API dokumentasi/discovery dapat diakses publik dan kontennya "
                             "terverifikasi (bukan fallback SPA). Surface ini dipakai attacker untuk "
                             "memetakan endpoint."),
                target=base + path,
                evidence=f"HTTP {r.status_code} · Content-Type: {ctype} · konten terverifikasi",
                cwe="CWE-200",
                confidence="confirmed",
                remediation=("Batasi akses dokumentasi API (auth/IP allowlist) dan hapus endpoint "
                             "dev yang tidak terpakai."),
            ))

        # GraphQL: hanya lapor bila introspection BENAR aktif (bukti pasti) atau UI nyata.
        for path in GRAPHQL_PATHS:
            url = base + path
            ri = client.post(url, json=GRAPHQL_INTROSPECTION)
            if ri is not None and ri.status_code < 400 and "__schema" in (ri.text or "") and "types" in (ri.text or ""):
                findings.append(Finding(
                    module="api_discovery",
                    title="GraphQL introspection aktif",
                    severity=Severity.HIGH,
                    description="Introspection mengizinkan siapa pun mengambil skema lengkap GraphQL.",
                    target=url,
                    evidence="POST introspection mengembalikan __schema.types",
                    cwe="CWE-200",
                    confidence="confirmed",
                    remediation="Nonaktifkan GraphQL introspection di produksi.",
                ))
                continue
            r = probe.verify_real(client, target, url,
                                  validator=lambda c, b: "graphiql" in b.lower() or "playground" in b.lower())
            if r is not None:
                findings.append(Finding(
                    module="api_discovery",
                    title=f"GraphQL IDE terbuka: {path}",
                    severity=Severity.LOW,
                    description="UI GraphQL (GraphiQL/Playground) dapat diakses publik.",
                    target=url,
                    evidence=f"HTTP {r.status_code} · UI GraphQL terverifikasi",
                    cwe="CWE-200",
                    confidence="confirmed",
                    remediation="Lindungi/hapus IDE GraphQL di produksi.",
                ))
    finally:
        client.close()
    return findings
