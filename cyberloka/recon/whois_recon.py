"""WHOIS lookup."""
from __future__ import annotations

from cyberloka.core import Finding, Severity, Target
from cyberloka.core.config import ScanConfig

try:
    import whois  # type: ignore
except ImportError:  # pragma: no cover
    whois = None  # type: ignore


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    if whois is None or target.is_ip:
        return []
    try:
        info = whois.whois(target.host)
    except Exception as e:  # noqa: BLE001
        return [
            Finding(
                module="whois",
                title="WHOIS lookup gagal",
                severity=Severity.INFO,
                description=f"Tidak dapat mengambil WHOIS: {e}",
                target=target.host,
            )
        ]
    interesting = {}
    for k in (
        "domain_name",
        "registrar",
        "creation_date",
        "expiration_date",
        "name_servers",
        "emails",
        "country",
        "org",
    ):
        v = getattr(info, k, None) or info.get(k) if hasattr(info, "get") else None
        if v:
            interesting[k] = str(v)

    return [
        Finding(
            module="whois",
            title="WHOIS information",
            severity=Severity.INFO,
            description="WHOIS publik berhasil diambil.",
            target=target.host,
            evidence="\n".join(f"{k}: {v}" for k, v in interesting.items()),
            remediation=(
                "Pertimbangkan WHOIS privacy / proxy untuk menyembunyikan informasi "
                "kontak dari publik (jika belum)."
            ),
            extra={"whois": interesting},
        )
    ]
