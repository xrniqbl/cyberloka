"""TLS / SSL audit."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from cyberloka.core import Finding, Severity, Target
from cyberloka.core.config import ScanConfig

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if target.scheme != "https":
        findings.append(
            Finding(
                module="tls",
                title="Situs tidak menggunakan HTTPS",
                severity=Severity.HIGH,
                description=(
                    "Target diakses lewat HTTP biasa. Trafik dapat disadap / dimodifikasi."
                ),
                target=target.base_url,
                remediation=(
                    "Sediakan sertifikat TLS (mis. Let's Encrypt) dan paksa redirect "
                    "HTTP -> HTTPS. Tambahkan HSTS setelah migrasi."
                ),
                references=["https://letsencrypt.org/"],
            )
        )
        return findings

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((target.host, target.port), timeout=config.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target.host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_bin = ssock.getpeercert(binary_form=True)
                proto = ssock.version()
                cipher = ssock.cipher()
    except Exception as e:  # noqa: BLE001
        findings.append(
            Finding(
                module="tls",
                title="Tidak dapat melakukan TLS handshake",
                severity=Severity.MEDIUM,
                description=f"TLS handshake gagal: {e}",
                target=f"{target.host}:{target.port}",
                remediation="Periksa konfigurasi TLS server.",
            )
        )
        return findings

    # Re-attempt with verification to detect chain/hostname issues
    verified = True
    verify_err = ""
    try:
        ctx2 = ssl.create_default_context()
        with socket.create_connection((target.host, target.port), timeout=config.timeout) as s2:
            with ctx2.wrap_socket(s2, server_hostname=target.host):
                pass
    except ssl.SSLCertVerificationError as e:
        verified = False
        verify_err = str(e)
    except Exception as e:  # noqa: BLE001
        verified = False
        verify_err = str(e)

    if not verified:
        findings.append(
            Finding(
                module="tls",
                title="Sertifikat TLS gagal diverifikasi",
                severity=Severity.HIGH,
                description=(
                    "Browser modern akan menolak koneksi. Penyebab umum: hostname "
                    "tidak cocok, sertifikat self-signed, atau chain incomplete."
                ),
                target=f"{target.host}:{target.port}",
                evidence=verify_err,
                remediation=(
                    "Gunakan sertifikat dari CA yang dipercaya, sertakan intermediate chain, "
                    "dan pastikan SAN mencakup hostname yang dipakai."
                ),
            )
        )

    # Protocol strength
    if proto in WEAK_PROTOCOLS:
        findings.append(
            Finding(
                module="tls",
                title=f"Protokol TLS lemah dipakai: {proto}",
                severity=Severity.HIGH,
                description=(
                    f"Server menegosiasikan {proto} yang sudah deprecated dan rentan "
                    "(POODLE, BEAST, dll.)."
                ),
                target=f"{target.host}:{target.port}",
                evidence=f"Negotiated: {proto} | cipher={cipher}",
                remediation=(
                    "Nonaktifkan SSLv2, SSLv3, TLS 1.0 dan TLS 1.1 di server. "
                    "Aktifkan minimal TLS 1.2 (lebih disarankan TLS 1.3)."
                ),
                references=["https://wiki.mozilla.org/Security/Server_Side_TLS"],
            )
        )

    # Expiry check
    not_after = cert.get("notAfter") if cert else None
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (exp - datetime.now(timezone.utc)).days
            if days_left < 0:
                sev = Severity.CRITICAL
                title = "Sertifikat TLS sudah kedaluwarsa"
            elif days_left < 14:
                sev = Severity.HIGH
                title = f"Sertifikat TLS hampir kedaluwarsa ({days_left} hari)"
            elif days_left < 30:
                sev = Severity.MEDIUM
                title = f"Sertifikat TLS akan kedaluwarsa dalam {days_left} hari"
            else:
                sev = Severity.INFO
                title = f"Sertifikat TLS valid ({days_left} hari)"

            findings.append(
                Finding(
                    module="tls",
                    title=title,
                    severity=sev,
                    description="Status masa berlaku sertifikat.",
                    target=f"{target.host}:{target.port}",
                    evidence=f"notAfter={not_after}",
                    remediation=(
                        "Aktifkan auto-renewal (mis. certbot/acme) jauh sebelum jatuh tempo."
                        if sev != Severity.INFO
                        else "Pertahankan rotasi sertifikat berkala."
                    ),
                )
            )
        except ValueError:
            pass

    # Cipher info
    if cipher:
        cname, cver, _ = cipher
        if "RC4" in cname or "DES" in cname or "MD5" in cname or "NULL" in cname:
            findings.append(
                Finding(
                    module="tls",
                    title=f"Cipher lemah: {cname}",
                    severity=Severity.HIGH,
                    description="Cipher klasik (RC4/DES/MD5) tidak lagi aman.",
                    target=f"{target.host}:{target.port}",
                    evidence=f"cipher={cname} ({cver})",
                    remediation=(
                        "Konfigurasi cipher suite modern. Lihat panduan Mozilla SSL "
                        "Configuration Generator."
                    ),
                    references=["https://ssl-config.mozilla.org/"],
                )
            )

    # Self-signed
    issuer = dict(x[0] for x in cert.get("issuer", [])) if cert else {}
    subject = dict(x[0] for x in cert.get("subject", [])) if cert else {}
    if issuer and subject and issuer == subject:
        findings.append(
            Finding(
                module="tls",
                title="Sertifikat self-signed terdeteksi",
                severity=Severity.HIGH,
                description=(
                    "Issuer == Subject. Self-signed certificate tidak dipercaya browser "
                    "publik dan rentan MITM."
                ),
                target=f"{target.host}:{target.port}",
                remediation="Gunakan sertifikat dari CA publik (mis. Let's Encrypt).",
            )
        )

    # extra summary info
    findings.append(
        Finding(
            module="tls",
            title="Ringkasan TLS",
            severity=Severity.INFO,
            description="Negosiasi TLS yang berhasil.",
            target=f"{target.host}:{target.port}",
            evidence=(
                f"protocol={proto}\ncipher={cipher}\nissuer={issuer}\nsubject={subject}"
            ),
            extra={
                "protocol": proto,
                "cipher": cipher,
                "issuer": issuer,
                "subject": subject,
                "cert_size": len(cert_bin) if cert_bin else 0,
            },
        )
    )

    return findings
