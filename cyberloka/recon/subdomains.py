"""Wordlist-based subdomain enumeration."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from cyberloka.core import Finding, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import load_data_lines


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    if target.is_ip:
        return []
    words = load_data_lines("subdomains.txt")
    if not words:
        return []
    base = target.host
    # avoid scanning bare TLDs
    if base.count(".") < 1:
        return []

    found: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(50, config.threads * 5)) as ex:
        futures = {ex.submit(_resolve, f"{w}.{base}"): w for w in words}
        for fut in as_completed(futures):
            w = futures[fut]
            ip = fut.result()
            if ip:
                found[f"{w}.{base}"] = ip

    if not found:
        return []

    return [
        Finding(
            module="subdomains",
            title=f"{len(found)} subdomain terdeteksi",
            severity=Severity.INFO,
            description=(
                "Subdomain ditemukan via brute-force wordlist. Setiap subdomain "
                "memperluas attack surface — pastikan semuanya di-monitor & di-patch."
            ),
            target=base,
            evidence="\n".join(f"{h} -> {ip}" for h, ip in sorted(found.items())),
            remediation=(
                "Inventarisasi semua subdomain. Hapus DNS record untuk service yang "
                "sudah tidak dipakai untuk mencegah subdomain takeover."
            ),
            references=[
                "https://owasp.org/www-community/attacks/Subdomain_Takeover",
            ],
            extra={"subdomains": found},
        )
    ]
