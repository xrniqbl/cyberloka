"""Host header injection detector.

Cek apakah server merefleksikan header Host yang dikirim attacker ke
response (mis. di link reset password, redirect, atau error page).

Jika dipantulkan, attacker dapat memalsukan email reset password (link
berubah ke domain attacker) atau cache poisoning.
"""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

EVIL_HOST = "evil-cyberloka.example.com"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # 1) Override Host header langsung
        resp = client.get(
            target.base_url,
            headers={"Host": EVIL_HOST},
            allow_redirects=False,
        )
        if resp is not None:
            body = resp.text or ""
            loc = resp.headers.get("Location", "")
            reflected_in_body = EVIL_HOST in body
            reflected_in_redirect = EVIL_HOST in loc

            if reflected_in_body or reflected_in_redirect:
                findings.append(
                    Finding(
                        module="host_header",
                        title="Host header injection: server merefleksikan Host attacker",
                        severity=Severity.HIGH,
                        description=(
                            "Server menggunakan nilai header Host yang dikirim klien "
                            "untuk membentuk URL/redirect. Attacker bisa memicu "
                            "password-reset email yang link-nya menuju domain mereka, "
                            "atau cache poisoning."
                        ),
                        target=target.base_url,
                        evidence=(
                            f"reflected_in_body={reflected_in_body}\n"
                            f"reflected_in_redirect={reflected_in_redirect}\n"
                            f"location={loc}\n"
                            f"snippet={truncate(body, 200)}"
                        ),
                        cwe="CWE-20",
                        remediation=(
                            "Whitelist nilai Host yang valid di reverse-proxy. "
                            "Pakai SERVER_NAME/canonical URL hard-coded saat bikin link "
                            "(jangan baca dari request). Reject request dengan Host yang "
                            "tidak ada di whitelist."
                        ),
                        references=[
                            "https://portswigger.net/web-security/host-header",
                        ],
                    )
                )

        # 2) X-Forwarded-Host (kalau dipakai reverse-proxy yang misconfigured)
        resp2 = client.get(
            target.base_url,
            headers={"X-Forwarded-Host": EVIL_HOST},
            allow_redirects=False,
        )
        if resp2 is not None:
            body2 = resp2.text or ""
            loc2 = resp2.headers.get("Location", "")
            if EVIL_HOST in body2 or EVIL_HOST in loc2:
                findings.append(
                    Finding(
                        module="host_header",
                        title="X-Forwarded-Host direfleksikan tanpa validasi",
                        severity=Severity.MEDIUM,
                        description=(
                            "Header X-Forwarded-Host (yang biasanya hanya dipercaya "
                            "dari reverse-proxy internal) direfleksikan ke output. "
                            "Bila server publik mempercayainya, attacker bisa "
                            "memanipulasi link generated."
                        ),
                        target=target.base_url,
                        evidence=f"location={loc2}\nbody_snippet={truncate(body2, 200)}",
                        cwe="CWE-20",
                        remediation=(
                            "Hanya percayai X-Forwarded-Host dari reverse-proxy internal "
                            "yang Anda kontrol. Jangan pernah pakai header user-controlled "
                            "untuk membentuk link reset password / verifikasi."
                        ),
                    )
                )
    finally:
        client.close()
    return findings
