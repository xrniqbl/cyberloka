"""WordPress XML-RPC: deteksi + validasi method berbahaya yang aktif.

Yang divalidasi:
  1. POST system.listMethods -> dapatkan daftar method
  2. Cek apakah pingback.ping & wp.getUsersBlogs ada (vektor amplifikasi DDoS
     dan brute-force amplifier 1 request = 1000 password)
  3. Konfirmasi pingback.ping dengan request kosong - kalau response berisi
     'parse error' = method aktif. Kalau 'method does not exist' = sudah disable.

Tidak melakukan brute-force / DDoS aktual - hanya verifikasi keberadaan method.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

LIST_METHODS_BODY = (
    '<?xml version="1.0"?>'
    "<methodCall><methodName>system.listMethods</methodName>"
    "<params></params></methodCall>"
)

PINGBACK_PROBE = (
    '<?xml version="1.0"?>'
    "<methodCall><methodName>pingback.ping</methodName>"
    "<params><param><value><string>http://invalid.invalid/</string></value></param>"
    "<param><value><string>http://invalid.invalid/</string></value></param>"
    "</params></methodCall>"
)

DANGEROUS_METHODS = {
    "pingback.ping": "Amplification DDoS (server target di-paksa kirim HTTP request ke korban)",
    "wp.getUsersBlogs": "Brute-force amplifier (1 request bisa kirim 1000 percobaan password)",
    "system.multicall": "Brute-force amplifier (multi-call wrapper)",
    "metaWeblog.editPost": "Modifikasi konten via XML-RPC",
}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.base_url
    xmlrpc_url = urljoin(base, "xmlrpc.php")
    client = HttpClient(config)
    try:
        # Step 1: cek endpoint exist
        head = client.get(xmlrpc_url)
        if head is None or head.status_code == 404:
            return findings
        body = head.text or ""
        if "XML-RPC server accepts POST" not in body and "xmlrpc" not in body.lower():
            return findings

        # Step 2: list methods
        r = client.post(
            xmlrpc_url,
            data=LIST_METHODS_BODY,
            headers={"Content-Type": "text/xml"},
        )
        if r is None or r.status_code != 200:
            return findings
        text = r.text or ""
        methods = re.findall(r"<string>([^<]+)</string>", text)
        if not methods:
            return findings

        present_dangerous = {m: DANGEROUS_METHODS[m] for m in DANGEROUS_METHODS if m in methods}
        if not present_dangerous:
            # XML-RPC enabled tapi method bahaya sudah dimatikan
            findings.append(Finding(
                module="wp_xmlrpc",
                target=xmlrpc_url,
                title=f"WordPress XML-RPC aktif ({len(methods)} method, tanpa method berbahaya)",
                severity=Severity.LOW,
                description=(
                    "XML-RPC dapat diakses publik, tapi method berbahaya seperti "
                    "pingback.ping dan wp.getUsersBlogs sudah dinonaktifkan. "
                    "Tetap rekomendasi untuk dimatikan total bila tidak dipakai."
                ),
                evidence=f"system.listMethods returned {len(methods)} methods",
                cwe="CWE-693",
                confidence="confirmed",
                urls=[xmlrpc_url],
                remediation="Block /xmlrpc.php di nginx/.htaccess, atau pakai plugin Disable XML-RPC.",
            ))
            return findings

        # Step 3: validasi pingback aktif via probe
        pingback_active = False
        if "pingback.ping" in present_dangerous:
            r2 = client.post(
                xmlrpc_url, data=PINGBACK_PROBE, headers={"Content-Type": "text/xml"}
            )
            if r2 is not None and "faultString" in (r2.text or ""):
                fb = r2.text or ""
                # Kalau muncul 'is not a valid URL' / 'invalid' / 'transport error' = method
                # benar-benar dieksekusi (cuma URL korban yang tidak valid). Itu konfirmasi
                # method aktif.
                if any(k in fb.lower() for k in (
                    "invalid url", "is not a valid", "transport error",
                    "tidak valid", "could not open"
                )):
                    pingback_active = True

        sev = Severity.HIGH if pingback_active else Severity.MEDIUM
        evidence = [
            f"endpoint   = {xmlrpc_url}",
            f"methods    = {len(methods)} total",
            "dangerous  = "
            + ", ".join(f"{m} ({d})" for m, d in present_dangerous.items()),
        ]
        if pingback_active:
            evidence.append("pingback.ping VERIFIED aktif via probe (faultString = invalid URL)")

        findings.append(Finding(
            module="wp_xmlrpc",
            target=xmlrpc_url,
            title=(
                f"WordPress XML-RPC + {len(present_dangerous)} method berbahaya"
                + (" (pingback.ping aktif - bisa untuk DDoS)" if pingback_active else "")
            ),
            severity=sev,
            description=(
                "XML-RPC WordPress aktif dengan method berbahaya. "
                + (
                    "pingback.ping yang aktif memungkinkan attacker memakai server Anda "
                    "sebagai amplifier DDoS terhadap korban lain - SERVER ANDA jadi "
                    "alat serangan, IP Anda bisa ter-blacklist secara internasional. "
                    if pingback_active else
                    "Method berbahaya terlihat ada di daftar; perlu dinonaktifkan."
                )
                + "wp.getUsersBlogs/system.multicall sering dipakai brute-force yang "
                "bypass rate-limit wp-login.php (1 request HTTP = 1000 percobaan)."
            ),
            evidence="\n".join(evidence),
            cwe="CWE-693",
            confidence="confirmed",
            urls=[xmlrpc_url],
            remediation=(
                "1. Block /xmlrpc.php di nginx atau .htaccess (return 403). Cara paling aman.\n"
                "2. Bila perlu XML-RPC (mis. Jetpack), pakai plugin 'Disable XML-RPC Pingback' "
                "untuk mematikan pingback saja.\n"
                "3. Aktifkan firewall (Wordfence) dengan rate-limit XML-RPC."
            ),
            references=[
                "https://www.wordfence.com/blog/2014/03/wordpress-pingback-vulnerability/",
                "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
            ],
        ))
    finally:
        client.close()
    return findings
