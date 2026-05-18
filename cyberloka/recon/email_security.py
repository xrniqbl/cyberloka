"""Email security: SPF, DKIM, DMARC, DNSSEC, CAA."""
from __future__ import annotations

import dns.resolver

from cyberloka.core import Finding, Severity, Target
from cyberloka.core.config import ScanConfig

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail",
                  "smtp", "dkim", "mandrill", "sendgrid", "mxvault")


def _resolve(name: str, rtype: str) -> list[str]:
    try:
        r = dns.resolver.Resolver()
        r.lifetime = 5.0
        return [a.to_text().strip('"') for a in r.resolve(name, rtype)]
    except Exception:  # noqa: BLE001
        return []


def run(target: Target, config: ScanConfig) -> list[Finding]:
    if target.is_ip:
        return []
    findings: list[Finding] = []
    host = target.host
    domain = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host

    # SPF
    spf = [t for t in _resolve(domain, "TXT") if t.lower().startswith("v=spf1")]
    if not spf:
        findings.append(Finding(
            module="email_security",
            title=f"SPF record tidak ditemukan untuk {domain}",
            severity=Severity.MEDIUM,
            description=("Domain tidak punya SPF record. Penyerang dapat memalsukan "
                         "alamat pengirim email seolah-olah dari domain Anda."),
            target=domain,
            cwe="CWE-290",
            remediation=("Tambahkan TXT record `v=spf1 include:_spf.google.com -all` "
                         "(atau provider mail Anda) untuk membatasi server pengirim sah."),
            references=["https://datatracker.ietf.org/doc/html/rfc7208"],
        ))
    elif any("+all" in s for s in spf):
        findings.append(Finding(
            module="email_security", title="SPF terlalu permisif (`+all`)",
            severity=Severity.HIGH, description="`+all` mengizinkan siapa pun mengirim atas nama domain.",
            target=domain, evidence=spf[0], cwe="CWE-290",
            remediation="Ganti `+all` → `-all` (hard fail) atau `~all` (soft fail).",
        ))

    # DMARC
    dmarc = _resolve(f"_dmarc.{domain}", "TXT")
    dmarc_v = [t for t in dmarc if t.lower().startswith("v=dmarc1")]
    if not dmarc_v:
        findings.append(Finding(
            module="email_security",
            title=f"DMARC record tidak ditemukan untuk {domain}",
            severity=Severity.HIGH,
            description=("Tanpa DMARC, MTA penerima tidak tahu apa yang harus "
                         "dilakukan saat SPF/DKIM gagal — phishing & spoofing dipermudah."),
            target=f"_dmarc.{domain}", cwe="CWE-345",
            remediation=("Mulai dengan policy ringan: "
                         "`v=DMARC1; p=none; rua=mailto:dmarc@{domain}`. "
                         "Setelah report bersih, naikkan ke `p=quarantine` lalu `p=reject`."),
            references=["https://datatracker.ietf.org/doc/html/rfc7489"],
        ))
    else:
        rec = dmarc_v[0].lower()
        if "p=none" in rec:
            findings.append(Finding(
                module="email_security", title="DMARC policy `p=none` (monitoring saja)",
                severity=Severity.MEDIUM,
                description="DMARC ada tapi tidak menolak email gagal autentikasi.",
                target=f"_dmarc.{domain}", evidence=dmarc_v[0], cwe="CWE-345",
                remediation="Setelah memantau report, ubah `p=none` → `p=quarantine` → `p=reject`.",
            ))

    # DKIM (best effort: cek beberapa selector umum)
    dkim_found = False
    for sel in DKIM_SELECTORS:
        rec = _resolve(f"{sel}._domainkey.{domain}", "TXT")
        if any("v=dkim1" in r.lower() or "k=rsa" in r.lower() for r in rec):
            dkim_found = True
            break
    if not dkim_found:
        findings.append(Finding(
            module="email_security",
            title=f"Tidak ada DKIM selector umum yang merespons di {domain}",
            severity=Severity.LOW,
            description=("Tidak ditemukan DKIM record di selector umum (default, google, "
                         "selector1/2, dll.). DKIM penting untuk integritas email."),
            target=domain, cwe="CWE-345",
            remediation=("Aktifkan DKIM pada provider mail dan publikasikan DKIM record "
                         "di DNS (selector ditentukan provider)."),
        ))

    # CAA
    caa = _resolve(domain, "CAA")
    if not caa:
        findings.append(Finding(
            module="email_security",
            title=f"CAA record tidak ditemukan untuk {domain}",
            severity=Severity.LOW,
            description=("Tanpa CAA, CA mana pun dapat menerbitkan sertifikat untuk "
                         "domain Anda — meningkatkan risiko mis-issuance."),
            target=domain, cwe="CWE-295",
            remediation=("Tambahkan CAA: `0 issue \"letsencrypt.org\"`, "
                         "`0 issuewild \"letsencrypt.org\"`, `0 iodef \"mailto:security@{domain}\"`."),
            references=["https://datatracker.ietf.org/doc/html/rfc8659"],
        ))

    # DNSSEC (cek DS record di parent zone via DNSKEY ada)
    dnskey = _resolve(domain, "DNSKEY")
    if not dnskey:
        findings.append(Finding(
            module="email_security",
            title=f"DNSSEC tampaknya tidak aktif di {domain}",
            severity=Severity.LOW,
            description=("Tidak ada DNSKEY record. DNSSEC memvalidasi integritas DNS "
                         "response dan mencegah cache poisoning."),
            target=domain, cwe="CWE-345",
            remediation="Aktifkan DNSSEC di registrar/DNS provider Anda dan publikasikan DS record di parent zone.",
        ))

    return findings
