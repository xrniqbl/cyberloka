"""Host header / X-Forwarded-Host injection probe."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

ATTACKER = "cyberloka-evil.invalid"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url, headers={"Host": ATTACKER}, allow_redirects=False)
        if r is not None and ATTACKER in (r.text or "")[:5000]:
            findings.append(Finding(
                module="host_header",
                title="Host header dipantulkan ke response",
                severity=Severity.MEDIUM,
                description=("Aplikasi memantulkan `Host` header yang dikontrol attacker. "
                             "Sering melahirkan password-reset poisoning (link reset diarahkan "
                             "ke domain attacker) atau cache poisoning."),
                target=target.base_url,
                evidence=f"Host: {ATTACKER} → reflected in response body",
                cwe="CWE-444",
                remediation=("Validasi `Host` header terhadap whitelist domain. "
                             "Bangun URL absolute dari konfigurasi server, bukan dari `Host`."),
            ))
        r2 = client.get(target.base_url, headers={"X-Forwarded-Host": ATTACKER},
                        allow_redirects=False)
        if r2 is not None:
            for h in ("Location", "Content-Location"):
                v = r2.headers.get(h)
                if v and ATTACKER in v:
                    findings.append(Finding(
                        module="host_header",
                        title=f"`X-Forwarded-Host` mempengaruhi header `{h}`",
                        severity=Severity.HIGH,
                        description=("Header `X-Forwarded-Host` dari attacker diteruskan ke "
                                     "URL absolute response. Ini jalan klasik untuk password-"
                                     "reset poisoning."),
                        target=target.base_url, evidence=f"{h}: {v}",
                        cwe="CWE-444",
                        remediation=("Pakai `trusted_proxies` whitelist di reverse proxy / "
                                     "framework (Django ALLOWED_HOSTS, Express trust proxy "
                                     "list). Jangan percayai header X-Forwarded-* dari klien."),
                    ))
                    break
    finally:
        client.close()
    return findings
