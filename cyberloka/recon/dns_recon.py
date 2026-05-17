"""DNS reconnaissance."""
from __future__ import annotations

from cyberloka.core import Finding, Severity, Target
from cyberloka.core.config import ScanConfig

try:
    import dns.resolver  # type: ignore
except ImportError:  # pragma: no cover
    dns = None  # type: ignore


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    if dns is None:
        return findings
    if target.is_ip:
        return findings

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    records: dict[str, list[str]] = {}

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(target.host, rtype)
            records[rtype] = [r.to_text() for r in answers]
        except Exception:  # noqa: BLE001
            continue

    if records:
        findings.append(
            Finding(
                module="dns",
                title="DNS records collected",
                severity=Severity.INFO,
                description=(
                    "Berhasil mengambil record DNS publik untuk domain. "
                    "Ini bukan kerentanan, tetapi berguna untuk attack-surface mapping."
                ),
                target=target.host,
                evidence="\n".join(
                    f"{k}: {', '.join(v)}" for k, v in records.items()
                ),
                remediation=(
                    "Pastikan tidak ada informasi sensitif (mis. internal IP, "
                    "service banner) yang bocor lewat TXT record. Audit "
                    "kebocoran SPF/DMARC/DKIM Anda."
                ),
                references=[
                    "https://owasp.org/www-community/Information_Gathering",
                ],
                extra={"records": records},
            )
        )

    # SPF / DMARC checks
    txt_records = records.get("TXT", [])
    has_spf = any("v=spf1" in t.lower() for t in txt_records)
    if not has_spf:
        findings.append(
            Finding(
                module="dns",
                title="SPF record tidak ditemukan",
                severity=Severity.LOW,
                description=(
                    "Domain tidak memiliki SPF record. SPF membantu mencegah "
                    "spoofing email atas nama domain Anda."
                ),
                target=target.host,
                remediation=(
                    'Tambahkan TXT record SPF, mis. "v=spf1 include:_spf.google.com -all".'
                ),
                references=["https://datatracker.ietf.org/doc/html/rfc7208"],
            )
        )

    # DMARC
    if not target.is_ip:
        try:
            ans = resolver.resolve(f"_dmarc.{target.host}", "TXT")
            dmarc_found = any("v=DMARC1" in r.to_text() for r in ans)
        except Exception:  # noqa: BLE001
            dmarc_found = False
        if not dmarc_found:
            findings.append(
                Finding(
                    module="dns",
                    title="DMARC record tidak ditemukan",
                    severity=Severity.LOW,
                    description=(
                        "Tidak ada DMARC record di _dmarc.<domain>. DMARC penting untuk "
                        "memberitahu mail receivers cara menangani email yang gagal SPF/DKIM."
                    ),
                    target=target.host,
                    remediation=(
                        'Tambahkan TXT record di _dmarc.<domain> seperti '
                        '"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com".'
                    ),
                    references=["https://datatracker.ietf.org/doc/html/rfc7489"],
                )
            )

    return findings
