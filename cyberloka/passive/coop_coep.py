"""Cross-Origin isolation header audit (COOP / COEP / CORP).

Tiga header yang menjadi standar isolasi cross-origin modern:

    * **Cross-Origin-Opener-Policy (COOP)**
        same-origin                -> aman (paling ketat)
        same-origin-allow-popups   -> sedang
        unsafe-none (default)      -> rentan window.opener-based attacks

    * **Cross-Origin-Embedder-Policy (COEP)**
        require-corp / credentialless -> aman
        unsafe-none (default)         -> tidak ada isolasi cross-origin

    * **Cross-Origin-Resource-Policy (CORP)**
        same-origin / same-site / cross-origin

Diperlukan COOP `same-origin` + COEP `require-corp` untuk fitur
`SharedArrayBuffer` & `performance.measureUserAgentSpecificMemory()`,
sekaligus mencegah serangan Spectre-class.

Hanya pembacaan header. Severity LOW.
"""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

GOOD_COOP = {"same-origin", "same-origin-allow-popups"}
GOOD_COEP = {"require-corp", "credentialless"}
GOOD_CORP = {"same-origin", "same-site"}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url, allow_redirects=True)
        if r is None:
            return findings

        coop = (r.headers.get("Cross-Origin-Opener-Policy", "") or "").strip().lower()
        coep = (r.headers.get("Cross-Origin-Embedder-Policy", "") or "").strip().lower()
        corp = (r.headers.get("Cross-Origin-Resource-Policy", "") or "").strip().lower()

        missing = []
        weak = []
        if not coop:
            missing.append("Cross-Origin-Opener-Policy")
        elif coop not in GOOD_COOP:
            weak.append(f"COOP={coop!r}")
        if not coep:
            missing.append("Cross-Origin-Embedder-Policy")
        elif coep not in GOOD_COEP:
            weak.append(f"COEP={coep!r}")
        if not corp:
            missing.append("Cross-Origin-Resource-Policy")
        elif corp not in GOOD_CORP and corp != "cross-origin":
            weak.append(f"CORP={corp!r}")

        if not missing and not weak:
            return findings

        if "Cross-Origin-Opener-Policy" in missing:
            findings.append(Finding(
                module="coop_coep",
                title="COOP (Cross-Origin-Opener-Policy) tidak diset",
                severity=Severity.LOW,
                description=(
                    "Tanpa COOP, `window.opener` dari halaman attacker "
                    "yang membuka site Anda dapat mengakses property "
                    "window halaman Anda (tabnabbing, "
                    "Spectre cross-origin). Set COOP `same-origin` agar "
                    "browser memaksa proses terpisah."
                ),
                target=target.base_url,
                evidence="Header Cross-Origin-Opener-Policy tidak ada",
                cwe="CWE-1021",
                confidence="confirmed",
                remediation=(
                    "Tambah `Cross-Origin-Opener-Policy: same-origin`. "
                    "Bila perlu izinkan popup OAuth, pakai "
                    "`same-origin-allow-popups`."
                ),
                references=[
                    "https://web.dev/coop-coep/",
                ],
            ))
        if "Cross-Origin-Embedder-Policy" in missing:
            findings.append(Finding(
                module="coop_coep",
                title="COEP (Cross-Origin-Embedder-Policy) tidak diset",
                severity=Severity.LOW,
                description=(
                    "Tanpa COEP, halaman ini tidak ter-isolate dari "
                    "resource cross-origin yang tidak opt-in CORP. "
                    "Konsekuensi: tidak bisa pakai `SharedArrayBuffer` "
                    "+ rentan terhadap Spectre cross-origin attack."
                ),
                target=target.base_url,
                evidence="Header Cross-Origin-Embedder-Policy tidak ada",
                cwe="CWE-1021",
                confidence="confirmed",
                remediation=(
                    "Tambah `Cross-Origin-Embedder-Policy: require-corp` "
                    "(setiap resource cross-origin harus serve CORP) atau "
                    "`credentialless` (browser fetch resource tanpa cookie)."
                ),
                references=["https://web.dev/coop-coep/"],
            ))
        if weak:
            findings.append(Finding(
                module="coop_coep",
                title=f"Header isolasi cross-origin nilai longgar: {', '.join(weak)}",
                severity=Severity.INFO,
                description=(
                    "Header ada tapi nilainya tidak menerapkan isolasi "
                    "ketat. Audit ulang kebutuhan."
                ),
                target=target.base_url,
                evidence=truncate(f"weak={weak}", 160),
                cwe="CWE-1021",
                confidence="confirmed",
                remediation=(
                    "Untuk COOP pakai `same-origin`. Untuk COEP pakai "
                    "`require-corp`. Untuk CORP pakai `same-origin` "
                    "(asset internal) atau `same-site` (CDN sendiri)."
                ),
            ))
    finally:
        client.close()
    return findings
