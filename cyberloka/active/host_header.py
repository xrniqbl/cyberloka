"""Host / X-Forwarded-Host header injection — strict-validation v0.10.4.

Sebelumnya: kalau string ``cyberloka-evil.invalid`` muncul di body, flag.
Tapi banyak template menampilkan host name dari ``Host`` header secara
default (mis. canonical link, og:url) yang bukan kerentanan praktis.

Sekarang: gunakan marker acak unik per request DAN cek bahwa marker
TIDAK muncul di response baseline (request normal). Hanya kalau marker
muncul setelah header attacker dikirim TAPI tidak ada di baseline,
finding dilaporkan.
"""
from __future__ import annotations

import secrets

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
)
from cyberloka.core.config import ScanConfig

ATTACKER_PREFIX = "cyberloka-evil"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # Baseline tanpa header injection
        base = client.get(target.base_url, allow_redirects=False)
        if base is None:
            return findings
        base_body = (base.text or "")[:8000]
        base_loc = base.headers.get("Location") or ""

        # 1) Reflection di body via Host header
        attacker_host = f"{ATTACKER_PREFIX}-{secrets.token_hex(3)}.invalid"
        r = client.get(
            target.base_url,
            headers={"Host": attacker_host},
            allow_redirects=False,
        )
        if r is not None:
            body = (r.text or "")[:8000]
            if attacker_host in body and attacker_host not in base_body:
                proof = ValidationProof(
                    method="random-marker+baseline-diff",
                    confirmed=True,
                    steps=[
                        "Baseline: GET tanpa Host attacker.",
                        f"Probe: GET dengan `Host: {attacker_host}`.",
                        "Marker unik muncul di response probe TAPI tidak di baseline -> reflektif.",
                    ],
                    samples=[f"Host: {attacker_host}"],
                )
                findings.append(Finding(
                    module="host_header",
                    title="Host header dipantulkan ke response (terkonfirmasi)",
                    severity=Severity.MEDIUM,
                    description=(
                        "Aplikasi memantulkan `Host` header yang dikontrol attacker "
                        "(marker tidak ada di baseline). Sering melahirkan password-"
                        "reset poisoning atau cache poisoning."
                    ),
                    target=target.base_url,
                    evidence=f"Host: {attacker_host} -> reflected (baseline clean)",
                    cwe="CWE-444",
                    confidence="confirmed",
                    urls=[target.base_url],
                    remediation=(
                        "Validasi `Host` header terhadap whitelist domain. "
                        "Bangun URL absolute dari konfigurasi server, bukan dari `Host`."
                    ),
                    extra=build_extra(proof=proof),
                ))

        # 2) X-Forwarded-Host -> mempengaruhi Location/Content-Location
        xfh = f"{ATTACKER_PREFIX}-xfh-{secrets.token_hex(3)}.invalid"
        r2 = client.get(
            target.base_url,
            headers={"X-Forwarded-Host": xfh},
            allow_redirects=False,
        )
        if r2 is not None:
            for h in ("Location", "Content-Location"):
                v = r2.headers.get(h)
                if not v or xfh not in v:
                    continue
                if xfh in base_loc:
                    continue  # baseline juga punya marker -> bukan reflektif
                proof = ValidationProof(
                    method="random-marker+baseline-diff",
                    confirmed=True,
                    steps=[
                        f"Baseline {h}: {base_loc!r}",
                        f"Probe X-Forwarded-Host: {xfh}",
                        f"{h} response probe memuat marker -> XFH dipakai server "
                        "untuk membentuk URL absolute.",
                    ],
                    samples=[f"{h}: {v}"],
                )
                findings.append(Finding(
                    module="host_header",
                    title=f"`X-Forwarded-Host` mempengaruhi header `{h}` (terkonfirmasi)",
                    severity=Severity.HIGH,
                    description=(
                        "Header `X-Forwarded-Host` dari attacker diteruskan ke "
                        "URL absolute response sementara baseline tidak. Jalan "
                        "klasik untuk password-reset poisoning."
                    ),
                    target=target.base_url,
                    evidence=f"{h}: {v}",
                    cwe="CWE-444",
                    confidence="confirmed",
                    urls=[target.base_url],
                    remediation=(
                        "Pakai `trusted_proxies` whitelist di reverse proxy / "
                        "framework (Django ALLOWED_HOSTS, Express trust proxy "
                        "list). Jangan percayai header X-Forwarded-* dari klien."
                    ),
                    extra=build_extra(proof=proof),
                ))
                break
    finally:
        client.close()
    return findings
