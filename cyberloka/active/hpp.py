"""HTTP Parameter Pollution (HPP) detector.

Cek apakah server menangani parameter duplikat dengan cara yang tidak
konsisten (misal: server pakai value pertama, sedangkan WAF/proxy pakai
value kedua -> bisa di-bypass).
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig


def _double_param(url: str, marker_a: str, marker_b: str) -> tuple[str, list[str]] | None:
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    if not pairs:
        return None
    new_pairs: list[tuple[str, str]] = []
    duplicated: list[str] = []
    for k, v in pairs:
        if not duplicated:  # duplicate hanya untuk param pertama
            new_pairs.append((k, marker_a))
            new_pairs.append((k, marker_b))
            duplicated.append(k)
        else:
            new_pairs.append((k, v))
    return urlunparse(p._replace(query=urlencode(new_pairs, doseq=True))), duplicated


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    discovered = getattr(target, "discovered", None)

    candidates: list[str] = []
    if "?" in target.base_url:
        candidates.append(target.base_url)
    if discovered is not None:
        for ep in getattr(discovered, "endpoints", []):
            if ep.method.upper() == "GET" and ep.params and "?" in ep.url:
                candidates.append(ep.url)
    candidates = list(dict.fromkeys(candidates))[:8]

    if not candidates:
        return findings

    client = HttpClient(config)
    try:
        for url in candidates:
            crafted = _double_param(url, "cyberlokaA", "cyberlokaB")
            if not crafted:
                continue
            mutated_url, dup_params = crafted
            resp = client.get(mutated_url)
            if resp is None:
                continue
            body = resp.text or ""

            saw_a = "cyberlokaA" in body
            saw_b = "cyberlokaB" in body

            # Inkonsistensi: hanya satu yang dipantulkan -> server pasti pilih satu.
            # Kalau bisa dideteksi mana yang dipakai, itu info untuk tester.
            if saw_a and not saw_b:
                ev = "server menggunakan value pertama (cyberlokaA)"
            elif saw_b and not saw_a:
                ev = "server menggunakan value kedua (cyberlokaB)"
            elif saw_a and saw_b:
                ev = "kedua value terlihat di response (mungkin di-concat)"
            else:
                continue  # tidak ada refleksi -> tidak conclusive

            findings.append(
                Finding(
                    module="hpp",
                    title=f"HTTP Parameter Pollution terdeteksi pada `{dup_params[0]}`",
                    severity=Severity.LOW,
                    confidence="tentative",
                    description=(
                        "Server memilih salah satu nilai ketika parameter dikirim "
                        "dua kali. Ini sendiri bukan kerentanan, tapi sering dipakai "
                        "untuk bypass WAF (WAF cek value pertama, app pakai value kedua)."
                    ),
                    target=mutated_url,
                    evidence=ev,
                    cwe="CWE-235",
                    remediation=(
                        "Tolak parameter duplikat di reverse-proxy/framework, atau "
                        "pastikan WAF + app pakai parser yang konsisten."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
                    ],
                )
            )
    finally:
        client.close()
    return findings
