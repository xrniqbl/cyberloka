"""Security header audit."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

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

INFO_LEAK_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None:
            return findings
        present = {k.lower(): v for k, v in resp.headers.items()}

        for hname, rule in HEADER_RULES.items():
            # special-case X-Frame-Options: ok if CSP frame-ancestors present
            if hname == "X-Frame-Options":
                csp = present.get("content-security-policy", "")
                if "frame-ancestors" in csp.lower():
                    continue
            if hname.lower() not in present:
                findings.append(
                    Finding(
                        module="headers",
                        title=f"Security header hilang: {hname}",
                        severity=rule["severity"],
                        description=rule["description"],
                        target=target.base_url,
                        remediation=rule["remediation"],
                        references=[rule["ref"]],
                    )
                )

        for h in INFO_LEAK_HEADERS:
            v = present.get(h.lower())
            if v:
                findings.append(
                    Finding(
                        module="headers",
                        title=f"Information disclosure via header `{h}`",
                        severity=Severity.LOW,
                        description=(
                            f"Header `{h}: {v}` membocorkan informasi versi/teknologi "
                            "yang membantu attacker mencari CVE relevan."
                        ),
                        target=target.base_url,
                        evidence=f"{h}: {v}",
                        remediation=(
                            f"Hapus atau samarkan header `{h}` di reverse-proxy / "
                            "framework (mis. `server_tokens off` di Nginx, "
                            "`expose_php=Off` di PHP)."
                        ),
                    )
                )
    finally:
        client.close()
    return findings
