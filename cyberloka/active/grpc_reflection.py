"""gRPC reflection-over-HTTP heuristic detection.

gRPC native reflection runs over HTTP/2 with a binary protocol; raw HTTP
clients tidak bisa langsung pakai. Modul ini melakukan deteksi heuristik:
  1. Probe `/grpc.reflection.v1alpha.ServerReflection` lewat HTTP POST.
  2. Periksa respons header `content-type: application/grpc*` ATAU
     status 415/200 dengan binary body khas gRPC.
  3. Coba juga gRPC-Web (`/grpc.reflection.v1.ServerReflection/...`)
     lewat POST `application/grpc-web+proto`.

Bila salah satu jalur balas dengan signature gRPC -> reflection terbuka.
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = [
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
]


def _looks_like_grpc(headers: dict) -> bool:
    ct = (headers.get("Content-Type") or "").lower()
    return ct.startswith(("application/grpc", "application/grpc-web"))


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            for content_type in ("application/grpc", "application/grpc-web+proto"):
                # Empty length-prefixed message (5 bytes header) — server gRPC
                # akan jawab signature gRPC walau payload kosong.
                body = b"\x00\x00\x00\x00\x00"
                r = client.post(url, data=body,
                                headers={"Content-Type": content_type,
                                         "TE": "trailers"},
                                allow_redirects=False)
                if r is None:
                    continue
                if r.status_code in (200, 415, 405) and _looks_like_grpc(dict(r.headers)):
                    findings.append(Finding(
                        module="grpc_reflection",
                        title="gRPC ServerReflection ter-expose di production",
                        severity=Severity.MEDIUM,
                        description=(
                            "Endpoint reflection gRPC merespons dengan header "
                            f"`content-type: {r.headers.get('Content-Type')}`. "
                            "Reflection sebaiknya dimatikan di production "
                            "karena memberi attacker schema lengkap service "
                            "(termasuk method admin) tanpa proto file."
                        ),
                        target=url,
                        urls=[url],
                        evidence=(
                            f"POST {url} CT={content_type} -> {r.status_code}; "
                            f"resp CT={r.headers.get('Content-Type')}"
                        ),
                        cwe="CWE-200",
                        confidence="firm",
                        remediation=(
                            "Hapus `reflection.Register(grpcServer)` di "
                            "production build. Pakai build-tag terpisah "
                            "(dev/staging only). Tambahkan auth interceptor "
                            "untuk semua method, termasuk reflection."
                        ),
                        references=[
                            "https://github.com/grpc/grpc/blob/master/doc/server-reflection.md",
                        ],
                    ))
                    return findings
    finally:
        client.close()
    return findings
