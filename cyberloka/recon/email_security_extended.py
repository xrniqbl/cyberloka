"""Extended email/MTA hardening checks: BIMI, MTA-STS, TLS-RPT."""
from __future__ import annotations

import dns.resolver

from cyberloka.core import Finding, Severity, Target
from cyberloka.core.config import ScanConfig


def _txt(name: str) -> list[str]:
    try:
        r = dns.resolver.Resolver()
        r.lifetime = 3.0
        return [a.to_text().strip('"') for a in r.resolve(name, "TXT")]
    except Exception:
        return []


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if target.is_ip:
        return findings
    domain = target.host
    if domain.startswith("www."):
        domain = domain[4:]

    # MTA-STS
    if not _txt(f"_mta-sts.{domain}"):
        findings.append(Finding(
            module="email_security_extended", target=domain,
            title=f"MTA-STS tidak dikonfigurasi untuk {domain}",
            severity=Severity.LOW,
            description="MTA-STS memaksa TLS untuk SMTP inbound. Tanpa ini, MITM downgrade mungkin.",
            cwe="CWE-319",
            remediation=("Publish TXT `_mta-sts.{domain} v=STSv1; id=...` dan host policy "
                         "di `https://mta-sts.{domain}/.well-known/mta-sts.txt`."),
        ))

    # TLS-RPT
    if not _txt(f"_smtp._tls.{domain}"):
        findings.append(Finding(
            module="email_security_extended", target=domain,
            title=f"TLS-RPT tidak dikonfigurasi",
            severity=Severity.LOW,
            description="Tanpa TLS-RPT, Anda tidak dapat report TLS handshake failure dari MTA penerima.",
            cwe="CWE-200",
            remediation=("Publish TXT `_smtp._tls.{domain} v=TLSRPTv1; rua=mailto:tls-reports@{domain}`."),
        ))

    # BIMI (anchor brand to authenticated email)
    bimi = _txt(f"default._bimi.{domain}")
    if not bimi:
        findings.append(Finding(
            module="email_security_extended", target=domain,
            title="BIMI tidak dikonfigurasi (logo brand di Gmail tidak muncul)",
            severity=Severity.INFO,
            description=("BIMI menampilkan logo brand di kotak masuk email. Hanya bisa dipasang "
                         "kalau DMARC sudah `p=quarantine` atau `p=reject`."),
            remediation="Publish `default._bimi.{domain} v=BIMI1; l=https://{domain}/logo.svg`.",
        ))

    return findings
