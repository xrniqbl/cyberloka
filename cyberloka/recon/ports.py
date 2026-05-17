"""TCP port scanner (connect scan)."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from cyberloka.core import Finding, Severity, Target
from cyberloka.core.config import ScanConfig

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    27017: "MongoDB",
    3000: "Node/Dev",
    3306: "MySQL",
    3389: "RDP",
    5000: "Flask/Dev",
    5432: "Postgres",
    5601: "Kibana",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "PHP-FPM",
    9200: "Elasticsearch",
    11211: "Memcached",
}

INSECURE_PORTS = {21: "FTP", 23: "Telnet", 2375: "Docker (no TLS)", 5900: "VNC", 6379: "Redis", 11211: "Memcached"}


def _check_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    host = target.resolve_ip() or target.host
    open_ports: dict[int, str] = {}
    with ThreadPoolExecutor(max_workers=min(50, config.threads * 5)) as ex:
        future_map = {
            ex.submit(_check_port, host, p, min(config.timeout, 2.0)): p
            for p in COMMON_PORTS
        }
        for fut in as_completed(future_map):
            port = future_map[fut]
            try:
                if fut.result():
                    open_ports[port] = COMMON_PORTS[port]
            except Exception:  # noqa: BLE001
                continue

    if open_ports:
        findings.append(
            Finding(
                module="ports",
                title=f"{len(open_ports)} port terbuka terdeteksi",
                severity=Severity.INFO,
                description="Daftar port TCP umum yang terbuka.",
                target=host,
                evidence="\n".join(f"{p}/tcp - {s}" for p, s in sorted(open_ports.items())),
                remediation=(
                    "Tutup port yang tidak diperlukan via firewall/security group. "
                    "Batasi akses port admin (SSH/RDP) hanya dari IP terpercaya."
                ),
                extra={"open_ports": open_ports},
            )
        )

        for p, name in open_ports.items():
            if p in INSECURE_PORTS:
                findings.append(
                    Finding(
                        module="ports",
                        title=f"Port tidak aman terbuka: {p}/{INSECURE_PORTS[p]}",
                        severity=Severity.HIGH,
                        description=(
                            f"Service {INSECURE_PORTS[p]} pada port {p} sering tidak terenkripsi "
                            "dan rentan disadap atau di-bruteforce."
                        ),
                        target=f"{host}:{p}",
                        remediation=(
                            "Matikan service ini di permukaan publik, atau minimal letakkan "
                            "di belakang VPN/bastion. Gunakan alternatif yang terenkripsi "
                            "(SFTP/SSH) bila perlu."
                        ),
                        references=[
                            "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                        ],
                    )
                )
    return findings
