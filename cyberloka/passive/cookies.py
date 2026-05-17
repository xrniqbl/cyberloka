"""Cookie attribute audit."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None:
            return findings
        # use raw set-cookie strings to inspect attributes
        set_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
        if not set_cookies:
            sc = resp.headers.get("Set-Cookie")
            set_cookies = [sc] if sc else []

        for raw in set_cookies:
            low = raw.lower()
            name = raw.split("=", 1)[0]
            problems = []
            if target.scheme == "https" and "secure" not in low:
                problems.append(("Secure", "tanpa flag `Secure`"))
            if "httponly" not in low:
                problems.append(("HttpOnly", "tanpa flag `HttpOnly`"))
            if "samesite" not in low:
                problems.append(("SameSite", "tanpa atribut `SameSite`"))

            if problems:
                missing = ", ".join(p[0] for p in problems)
                findings.append(
                    Finding(
                        module="cookies",
                        title=f"Cookie `{name}` kekurangan atribut keamanan: {missing}",
                        severity=Severity.MEDIUM,
                        description=(
                            "Cookie sesi/auth tanpa flag yang tepat dapat disadap (Secure), "
                            "diakses JavaScript untuk XSS theft (HttpOnly), atau dipakai untuk "
                            "CSRF cross-site (SameSite)."
                        ),
                        target=target.base_url,
                        evidence=raw,
                        remediation=(
                            "Set semua cookie sensitif dengan `Secure; HttpOnly; SameSite=Lax` "
                            "(atau `Strict` untuk cookie auth murni). Untuk konteks cross-site "
                            "yang sah gunakan `SameSite=None; Secure`."
                        ),
                        references=[
                            "https://owasp.org/www-community/controls/SecureCookieAttribute",
                        ],
                    )
                )
    finally:
        client.close()
    return findings
