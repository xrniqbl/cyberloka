"""Kubernetes API / dashboard / kubelet exposure."""
from __future__ import annotations

import socket
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

K8S_PATHS = [
    "/api/v1/namespaces", "/api/v1/pods", "/version",
    "/healthz", "/openapi/v2", "/api",
    "/metrics", "/livez",
]
DASHBOARD_PATHS = [
    "/api/v1/login", "/", "/api/v1/settings/global",
]


def _check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    host = target.resolve_ip() or target.host
    client = HttpClient(config)
    try:
        # Cek port khas k8s
        for port, label in [(6443, "API server"), (10250, "kubelet"),
                             (10255, "kubelet read-only"), (2379, "etcd"),
                             (8443, "dashboard")]:
            if not _check_port(host, port):
                continue
            for path in K8S_PATHS[:5]:
                r = client.get(f"https://{host}:{port}{path}")
                if r is None:
                    continue
                body = r.text or ""
                low = body.lower()
                # Sinyal kuat khas API/kubelet k8s — bukan sekadar kata "kind" yang umum.
                strong = (
                    ("apiversion" in low and "kind" in low)
                    or "kubernetes" in low
                    or '"paths"' in low and "/api" in low
                    or "\"major\"" in low and "\"minor\"" in low
                )
                if strong:
                    findings.append(Finding(
                        module="k8s_exposure", target=f"https://{host}:{port}{path}",
                        title=f"Kubernetes {label} dapat diakses",
                        severity=Severity.CRITICAL if port in (6443, 10250) else Severity.HIGH,
                        description=("Kubernetes endpoint terbuka tanpa autentikasi proper. "
                                     "Jika anonymous-auth atau bocoran kubelet, attacker bisa "
                                     "exec ke pod, baca semua secret, dan ambil alih cluster."),
                        evidence=f"HTTP {r.status_code}, len={len(body)}",
                        cwe="CWE-306",
                        remediation=("Aktifkan RBAC + nonaktifkan anonymous-auth, "
                                     "letakkan API server di balik VPN. Untuk kubelet: "
                                     "`--anonymous-auth=false --authorization-mode=Webhook`."),
                        references=["https://kubernetes.io/docs/concepts/security/"],
                    ))
                    break
    finally:
        client.close()
    return findings
