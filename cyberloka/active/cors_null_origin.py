"""CORS Origin: null reflection with credentials."""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

API_PATHS = [
    "/api/me", "/api/user", "/api/profile", "/api/users/me",
    "/me", "/account", "/api/account", "/api/v1/me", "/api/v2/me",
    "/api/session", "/api/auth/me", "/graphql",
]


def _check(headers: dict, origin: str) -> str | None:
    aco = headers.get("Access-Control-Allow-Origin")
    acc = (headers.get("Access-Control-Allow-Credentials") or "").lower()
    if not aco:
        return None
    if aco.strip() == origin and acc == "true":
        return f"ACAO={aco!r} + ACAC=true"
    if aco.strip() == "*" and acc == "true":
        # Browser sebenarnya menolak ini, tapi tetap misconfig serius
        return f"ACAO=* + ACAC=true (broken config)"
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in API_PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            for origin in ("null", "https://attacker.example.com"):
                r = client.get(url, headers={"Origin": origin},
                               allow_redirects=False)
                if r is None or r.status_code >= 500:
                    continue
                hit = _check(dict(r.headers), origin)
                if not hit:
                    continue
                sev = Severity.HIGH
                title = (f"CORS rentan: Origin: {origin} dipantulkan + "
                         f"credentials true di {path}")
                if origin == "null":
                    title = (f"CORS Origin: null + Allow-Credentials true di {path}")
                findings.append(Finding(
                    module="cors_null_origin",
                    title=title,
                    severity=sev,
                    description=(
                        "Server mengembalikan `Access-Control-Allow-Origin` "
                        "sesuai input attacker dengan `Allow-Credentials: true`. "
                        "Halaman attacker dapat membaca response API privat "
                        "atas nama korban yang sedang login."
                    ),
                    target=url,
                    urls=[url],
                    evidence=f"GET {url} Origin={origin} -> {hit}",
                    cwe="CWE-942",
                    confidence="confirmed",
                    remediation=(
                        "Whitelist origin secara eksplisit (jangan reflect "
                        "Origin sembarangan). Untuk `null`, tolak — tidak ada "
                        "use-case legitimate untuk endpoint authenticated. "
                        "Bila perlu credentials cross-origin, set ACAC=true "
                        "HANYA untuk origin terdaftar."
                    ),
                    references=[
                        "https://portswigger.net/web-security/cors",
                    ],
                ))
                break
            if findings:
                break
    finally:
        client.close()
    return findings
