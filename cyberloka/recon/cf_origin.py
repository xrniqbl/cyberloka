"""Try to find origin IP behind Cloudflare via non-proxied subdomains."""
from __future__ import annotations

import socket

import dns.resolver

from cyberloka.core import Finding, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import load_data_lines

CF_RANGES = (
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
    "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.",
    "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.",
    "162.158.", "162.159.",
    "131.0.72.", "108.162.",
    "141.101.", "190.93.", "188.114.",
    "197.234.240.", "198.41.",
)


def _is_cf(ip: str) -> bool:
    return any(ip.startswith(p) for p in CF_RANGES)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    if target.is_ip:
        return []
    apex = target.host
    findings: list[Finding] = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0

    # Cek apakah target memang di belakang Cloudflare
    try:
        a_records = [str(a) for a in resolver.resolve(apex, "A")]
    except Exception:  # noqa: BLE001
        return findings
    if not any(_is_cf(ip) for ip in a_records):
        return findings  # bukan Cloudflare, modul ini tidak relevan

    # Subdomain umum yang sering tidak diproxy CF
    candidates = ["mail", "ftp", "cpanel", "direct", "origin", "old", "dev",
                  "staging", "vpn", "ns1", "ns2", "smtp", "webmail", "mx"]
    extra = load_data_lines("subdomains.txt")[:30]
    for c in extra:
        if c not in candidates:
            candidates.append(c)

    leaked: list[tuple[str, str]] = []
    for sub in candidates[:40]:
        host = f"{sub}.{apex}"
        try:
            ans = resolver.resolve(host, "A")
            for a in ans:
                ip = str(a)
                if not _is_cf(ip):
                    leaked.append((host, ip))
                    break
        except Exception:  # noqa: BLE001
            continue

    if leaked:
        findings.append(Finding(
            module="cf_origin",
            title=f"{len(leaked)} subdomain merujuk ke IP di luar Cloudflare",
            severity=Severity.MEDIUM,
            description=("Beberapa subdomain tidak melewati Cloudflare. Jika alamat-alamat "
                         "ini juga melayani aplikasi utama, attacker dapat melewati WAF "
                         "Cloudflare dengan menyerang origin langsung."),
            target=apex,
            evidence="\n".join(f"{h} → {ip}" for h, ip in leaked[:10]),
            cwe="CWE-693",
            remediation=("Pastikan firewall origin hanya menerima IP Cloudflare "
                         "(https://www.cloudflare.com/ips/), atau pakai Cloudflare Tunnel. "
                         "Jangan publikasikan IP origin lewat MX/cPanel/staging."),
        ))
    return findings


def _socket_ok(host: str, port: int = 443, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
