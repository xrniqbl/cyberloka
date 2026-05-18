"""Cache-Control audit on potentially sensitive pages."""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# Pages that usually carry user-specific data
SENSITIVE_PATHS = [
    "/", "/account", "/profile", "/dashboard", "/admin",
    "/settings", "/billing", "/orders", "/me", "/user",
]

WEAK_DIRECTIVES = ("public", "max-age=", "s-maxage=")
STRONG_DIRECTIVES = ("no-store", "no-cache", "private")


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in SENSITIVE_PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code >= 400:
                continue
            cc = r.headers.get("Cache-Control", "").lower()
            pragma = r.headers.get("Pragma", "").lower()
            # If response sets cookies (likely user data) and cache is permissive
            sets_cookie = "Set-Cookie" in r.headers or any(c for c in r.cookies)
            has_strong = any(d in cc for d in STRONG_DIRECTIVES) or "no-cache" in pragma
            looks_public = (not cc) or (any(d in cc for d in WEAK_DIRECTIVES) and not has_strong)

            if sets_cookie and looks_public:
                findings.append(
                    Finding(
                        module="cache",
                        title=f"Halaman kemungkinan cacheable padahal mengirim cookie: {url}",
                        severity=Severity.MEDIUM,
                        description=(
                            "Halaman kemungkinan menyajikan konten user-specific (mengirim "
                            "Set-Cookie) tetapi tidak melarang caching. Jika ada shared "
                            "proxy/CDN, response satu user bisa terlihat user lain."
                        ),
                        target=url,
                        evidence=f"Cache-Control: {cc!r}\nPragma: {pragma!r}",
                        cwe="CWE-525",
                        remediation=(
                            "Untuk halaman terotentikasi gunakan "
                            "`Cache-Control: no-store` (atau minimal `private, no-cache`). "
                            "Pastikan CDN tidak mem-bypass header tersebut."
                        ),
                        references=[
                            "https://datatracker.ietf.org/doc/html/rfc7234",
                        ],
                    )
                )
    finally:
        client.close()
    return findings
