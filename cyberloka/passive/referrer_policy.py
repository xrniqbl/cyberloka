"""Referrer-Policy header audit.

Header `Referrer-Policy` mengontrol seberapa banyak informasi URL halaman
asal di-share ke tujuan saat user mengklik link / browser memuat resource.

Nilai aman:
    no-referrer
    no-referrer-when-downgrade
    same-origin
    strict-origin
    strict-origin-when-cross-origin   (rekomendasi default modern)

Nilai BERBAHAYA (membocorkan URL lengkap termasuk query params):
    unsafe-url
    no-referrer-when-downgrade        (info bocor saat HTTP→HTTPS sama)
    origin-when-cross-origin          (membocorkan origin asal di setiap nav)
    "" (kosong / tidak diset)         -> default browser = no-referrer-when-downgrade

Validasi: hanya baca header, finding pasti firm (no probe risk). Severity
LOW kecuali halaman login/payment yang lebih sensitif.
"""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

GOOD_VALUES = {
    "no-referrer", "same-origin", "strict-origin",
    "strict-origin-when-cross-origin",
}
WEAK_VALUES = {
    "unsafe-url",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
}


def _classify(value: str) -> tuple[str, Severity, str]:
    """Return (label, severity, recommendation)."""
    v = (value or "").strip().lower()
    if not v:
        return ("tidak diset (default browser)",
                Severity.LOW,
                "Set `Referrer-Policy: strict-origin-when-cross-origin` "
                "secara eksplisit di reverse-proxy / framework. Default "
                "browser bervariasi dan beberapa browser lama membocorkan "
                "URL lengkap.")
    if v in WEAK_VALUES:
        return (f"longgar (`{v}`)",
                Severity.LOW,
                "Ganti ke `strict-origin-when-cross-origin` atau "
                "`no-referrer` untuk halaman sensitif (login, payment, "
                "reset-password). Hindari `unsafe-url` sama sekali.")
    if v in GOOD_VALUES:
        return ("aman", Severity.INFO, "")
    return (f"nilai tidak dikenal (`{v}`)",
            Severity.LOW,
            "Periksa typo. Pakai salah satu nilai standar W3C.")


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url, allow_redirects=True)
        if r is None:
            return findings
        value = r.headers.get("Referrer-Policy", "")
        label, sev, rec = _classify(value)
        if sev == Severity.INFO:
            return findings  # aman, jangan rame-ramein report

        findings.append(Finding(
            module="referrer_policy",
            title=f"Referrer-Policy {label}",
            severity=sev,
            description=(
                "Header `Referrer-Policy` menentukan seberapa banyak URL "
                "halaman asal yang dikirim ke domain lain saat user "
                "klik link / browser load resource. Nilai longgar / "
                "kosong dapat membocorkan URL berisi token reset-password, "
                "session id di query, atau path internal."
            ),
            target=target.base_url,
            evidence=truncate(f"Referrer-Policy: {value!r}", 160),
            cwe="CWE-200",
            confidence="confirmed",
            remediation=rec,
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                "https://web.dev/referrer-best-practices/",
            ],
            extra={"reverify": {"status": (200, 301, 302)}},
        ))
    finally:
        client.close()
    return findings
