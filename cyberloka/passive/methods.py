"""HTTP method enumeration / dangerous methods."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

DANGEROUS = {"PUT", "DELETE", "TRACE", "TRACK", "CONNECT"}


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.options(target.base_url)
        allow = ""
        if resp is not None:
            allow = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
        allowed = {m.strip().upper() for m in allow.split(",") if m.strip()}

        # Active probe for TRACE
        trace_resp = client.request("TRACE", target.base_url, allow_redirects=False)
        trace_enabled = trace_resp is not None and trace_resp.status_code == 200 and "TRACE" in (trace_resp.text or "").upper()

        if trace_enabled:
            findings.append(
                Finding(
                    module="methods",
                    title="HTTP TRACE diaktifkan (Cross-Site Tracing risk)",
                    severity=Severity.MEDIUM,
                    description=(
                        "TRACE me-mantulkan header request ke client; bila dipakai bersama "
                        "vulnerability lain, dapat membocorkan cookie HttpOnly."
                    ),
                    target=target.base_url,
                    remediation=(
                        "Nonaktifkan TRACE/TRACK di web server "
                        "(`TraceEnable Off` di Apache, blok di Nginx, atau di reverse proxy)."
                    ),
                )
            )

        risky = allowed & DANGEROUS
        if risky:
            findings.append(
                Finding(
                    module="methods",
                    title=f"Metode HTTP berisiko diizinkan: {', '.join(sorted(risky))}",
                    severity=Severity.MEDIUM,
                    description=(
                        "Server mengiklankan metode yang jarang dibutuhkan publik. "
                        "Bila tidak dilindungi auth, dapat dipakai untuk write/delete content."
                    ),
                    target=target.base_url,
                    evidence=f"Allow: {allow}",
                    remediation=(
                        "Whitelist metode di reverse-proxy / framework (`GET, HEAD, POST` saja "
                        "untuk endpoint publik). Pastikan endpoint write hanya dapat diakses "
                        "dengan otentikasi yang benar."
                    ),
                )
            )
    finally:
        client.close()
    return findings
