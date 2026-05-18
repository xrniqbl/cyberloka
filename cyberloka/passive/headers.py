"""Security header audit.

Akurasi:

- ``Server: cloudflare`` / ``Server: nginx`` (tanpa versi) → INFO saja, bukan
  disclosure.
- ``Server: Apache/2.4.41 (Ubuntu)`` → versi expose → LOW.
- ``X-Powered-By: PHP/7.4.3`` → LOW.
- HSTS present tapi `max-age` < 6 bulan → LOW (informasional).
- CSP present tapi sangat lemah (mis. `default-src *`) → MEDIUM.
"""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")
WEAK_CSP_RE = re.compile(
    r"(default-src\s+[^;]*\*\b|"
    r"script-src\s+[^;]*'unsafe-inline'|"
    r"script-src\s+[^;]*\*\b|"
    r"object-src\s+[^;]*\*\b)",
    re.I,
)


HEADER_RULES = {
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": (
            "Content-Security-Policy (CSP) tidak diset. CSP adalah pertahanan utama "
            "terhadap XSS dan data injection."
        ),
        "remediation": (
            "Tambahkan header CSP yang ketat, mis.: "
            "`Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'`."
        ),
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/CSP",
    },
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "description": (
            "HSTS (Strict-Transport-Security) tidak diset. Tanpa HSTS, browser "
            "rentan terhadap downgrade attack ke HTTP."
        ),
        "remediation": (
            "Tambahkan: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. "
            "Pastikan situs sudah full HTTPS sebelum mengaktifkan preload."
        ),
        "ref": "https://datatracker.ietf.org/doc/html/rfc6797",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": (
            "X-Frame-Options tidak diset (dan CSP frame-ancestors juga tidak). "
            "Halaman dapat di-iframe di situs lain → clickjacking."
        ),
        "remediation": (
            "Set `X-Frame-Options: DENY` atau gunakan "
            "`Content-Security-Policy: frame-ancestors 'self'`."
        ),
        "ref": "https://owasp.org/www-community/attacks/Clickjacking",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": (
            "X-Content-Type-Options tidak diset. Browser dapat melakukan MIME-sniffing "
            "yang dapat menyebabkan XSS pada upload file."
        ),
        "remediation": "Tambahkan `X-Content-Type-Options: nosniff` di semua respons.",
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": (
            "Referrer-Policy tidak diset. Browser dapat mengirim URL lengkap "
            "(termasuk token) ke domain pihak ketiga lewat header Referer."
        ),
        "remediation": (
            "Set `Referrer-Policy: strict-origin-when-cross-origin` atau yang lebih ketat."
        ),
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": (
            "Permissions-Policy tidak diset. Tanpa header ini, fitur browser "
            "(camera, mic, geolocation, dsb.) bisa dipakai oleh skrip pihak ketiga."
        ),
        "remediation": (
            "Set whitelist eksplisit, mis.: "
            "`Permissions-Policy: geolocation=(), camera=(), microphone=()`."
        ),
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy",
    },
}

INFO_LEAK_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator")


def _csp_too_weak(value: str) -> str | None:
    if not value:
        return None
    m = WEAK_CSP_RE.search(value)
    return m.group(1) if m else None


def _hsts_short(value: str) -> int | None:
    """Return max-age in seconds when CSP is too short, else None."""
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    if not m:
        return None
    age = int(m.group(1))
    if age < 60 * 60 * 24 * 180:  # 6 months
        return age
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None:
            return findings
        present = {k.lower(): v for k, v in resp.headers.items()}

        # Missing-header rules
        for hname, rule in HEADER_RULES.items():
            value = present.get(hname.lower(), "")
            if hname == "X-Frame-Options":
                csp = present.get("content-security-policy", "")
                if "frame-ancestors" in csp.lower():
                    continue
            if not value:
                findings.append(
                    Finding(
                        module="headers",
                        title=f"Security header hilang: {hname}",
                        severity=rule["severity"],
                        description=rule["description"],
                        target=target.base_url,
                        remediation=rule["remediation"],
                        confidence="firm",
                        references=[rule["ref"]],
                    )
                )
                continue

            # Header ada — periksa kekuatan.
            if hname == "Content-Security-Policy":
                weak = _csp_too_weak(value)
                if weak:
                    findings.append(
                        Finding(
                            module="headers",
                            title=f"CSP terlalu permisif ({weak})",
                            severity=Severity.MEDIUM,
                            description=(
                                "CSP terdeteksi mengizinkan wildcard atau 'unsafe-inline'. "
                                "Efektivitasnya menurun drastis."
                            ),
                            target=target.base_url,
                            evidence=f"CSP: {value}",
                            confidence="confirmed",
                            remediation=(
                                "Hapus wildcard `*` dan `'unsafe-inline'`. Gunakan nonce/hash "
                                "untuk script inline yang memang dibutuhkan."
                            ),
                            references=[
                                "https://csp-evaluator.withgoogle.com/",
                            ],
                        )
                    )
            elif hname == "Strict-Transport-Security":
                age = _hsts_short(value)
                if age is not None:
                    findings.append(
                        Finding(
                            module="headers",
                            title=f"HSTS max-age terlalu pendek ({age}s)",
                            severity=Severity.LOW,
                            description=(
                                "max-age di bawah 6 bulan kurang efektif. Browser bisa "
                                "lupa kebijakan dan kembali rentan downgrade."
                            ),
                            target=target.base_url,
                            evidence=f"HSTS: {value}",
                            confidence="confirmed",
                            remediation=(
                                "Set `max-age=31536000` (1 tahun) dan tambahkan "
                                "`includeSubDomains` jika subdomain juga HTTPS."
                            ),
                        )
                    )

        # Information disclosure
        for h in INFO_LEAK_HEADERS:
            v = present.get(h.lower())
            if not v:
                continue
            has_version = bool(VERSION_RE.search(v))
            sev = Severity.LOW if has_version else Severity.INFO
            findings.append(
                Finding(
                    module="headers",
                    title=f"Information disclosure via header `{h}`",
                    severity=sev,
                    description=(
                        f"Header `{h}: {v}` "
                        + (
                            "membocorkan informasi versi/teknologi yang membantu attacker "
                            "mencari CVE relevan."
                            if has_version
                            else "menampilkan teknologi yang dipakai (tanpa versi spesifik). "
                            "Risiko rendah."
                        )
                    ),
                    target=target.base_url,
                    evidence=f"{h}: {v}",
                    confidence="confirmed",
                    remediation=(
                        f"Hapus atau samarkan header `{h}` di reverse-proxy / framework "
                        "(`server_tokens off` di Nginx, `expose_php=Off` di PHP, "
                        "`ServerTokens Prod` di Apache)."
                    ),
                )
            )
    finally:
        client.close()
    return findings
