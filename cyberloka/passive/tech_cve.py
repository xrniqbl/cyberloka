"""Cek versi teknologi terhadap minimum-known-secure version.

Bukan database CVE penuh — tapi mendeteksi versi yang JELAS usang:
- nginx < 1.20
- Apache < 2.4.50
- PHP < 7.4 atau < 8.0
- jQuery < 3.5
- WordPress < 6.0
- OpenSSL < 1.1.1

Ini cukup untuk menangkap "low-hanging fruit". Untuk audit menyeluruh,
gunakan tool dedicated seperti nuclei / wpscan / nmap NSE.
"""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# Pattern: (regex untuk extract versi, label, min_secure_version, severity)
_RULES: list[tuple[re.Pattern[str], str, tuple[int, ...], Severity]] = [
    (re.compile(r"nginx/(\d+\.\d+(?:\.\d+)?)", re.I), "nginx", (1, 20), Severity.MEDIUM),
    (re.compile(r"Apache/(\d+\.\d+(?:\.\d+)?)", re.I), "Apache httpd", (2, 4, 50), Severity.MEDIUM),
    (re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.I), "PHP", (8, 0), Severity.HIGH),
    (re.compile(r"jQuery v?(\d+\.\d+(?:\.\d+)?)", re.I), "jQuery", (3, 5), Severity.LOW),
    (re.compile(r"WordPress\s+(\d+\.\d+(?:\.\d+)?)", re.I), "WordPress", (6, 0), Severity.HIGH),
    (re.compile(r"OpenSSL/(\d+\.\d+\.\d+[a-z]?)", re.I), "OpenSSL", (1, 1, 1), Severity.HIGH),
    (re.compile(r"IIS/(\d+\.\d+)", re.I), "IIS", (10, 0), Severity.MEDIUM),
    (re.compile(r"Tomcat/(\d+\.\d+(?:\.\d+)?)", re.I), "Tomcat", (9, 0), Severity.HIGH),
]


def _ver_tuple(v: str) -> tuple[int, ...]:
    parts: list[int] = []
    for p in v.split("."):
        m = re.match(r"(\d+)", p)
        if not m:
            break
        parts.append(int(m.group(1)))
    return tuple(parts)


def _is_outdated(v: str, minimum: tuple[int, ...]) -> bool:
    cur = _ver_tuple(v)
    if not cur:
        return False
    return cur < minimum


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None:
            return findings
        haystacks: list[str] = []
        for k in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
            v = resp.headers.get(k)
            if v:
                haystacks.append(f"header:{k}={v}")
        if resp.text:
            haystacks.append(resp.text[:50_000])  # cap

        for hay in haystacks:
            for rgx, label, minimum, sev in _RULES:
                m = rgx.search(hay)
                if not m:
                    continue
                ver = m.group(1)
                if _is_outdated(ver, minimum):
                    findings.append(
                        Finding(
                            module="tech_cve",
                            title=f"{label} versi usang terdeteksi: {ver}",
                            severity=sev,
                            description=(
                                f"{label} {ver} sudah lebih lama dari versi minimum aman yang "
                                f"direkomendasikan ({'.'.join(str(x) for x in minimum)}). Versi ini "
                                "kemungkinan punya CVE publik yang bisa langsung dieksploitasi."
                            ),
                            target=target.base_url,
                            evidence=f"{label} {ver} (min secure: {'.'.join(str(x) for x in minimum)})",
                            cwe="CWE-1395",
                            remediation=(
                                f"Upgrade {label} ke versi terbaru. Cek changelog & "
                                "advisory keamanan di situs resmi vendor. Jadwalkan patching rutin."
                            ),
                            references=[
                                f"https://www.cvedetails.com/vendor-search.php?search={label}",
                            ],
                        )
                    )
    finally:
        client.close()
    return findings
