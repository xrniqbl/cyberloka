"""HTTP Parameter Pollution probe — strict-validation v0.10.4.

Sebelumnya: setiap perbedaan length > 50 byte ditandai HPP. Banyak halaman
dynamic memang menghasilkan length berbeda antar request, sehingga banyak
false-positive.

Sekarang: ambil DUA baseline (request sama dua kali) untuk mengukur jitter
natural. HPP hanya dikonfirmasi kalau perubahan length saat polluted
**lebih besar** dari ``max(150 byte, 3x jitter)`` ATAU status code
berubah.
"""
from __future__ import annotations

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


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    state = get_state(config)
    urls = (state.param_urls if state else []) + [target.base_url]
    seen_keys: set[tuple[str, str]] = set()
    client = HttpClient(config)
    try:
        for url in urls[:10]:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if not params:
                continue
            k, _ = params[0]
            if (parsed.netloc, k) in seen_keys:
                continue
            seen_keys.add((parsed.netloc, k))

            # Dua baseline untuk mengukur jitter natural.
            base_a = client.get(url)
            base_b = client.get(url)
            if base_a is None or base_b is None:
                continue
            len_a = len(base_a.text or "")
            len_b = len(base_b.text or "")
            jitter = abs(len_a - len_b)
            base_avg = (len_a + len_b) / 2

            polluted = list(params) + [(k, "cyberloka-pollute")]
            mutated = urlunparse(parsed._replace(query=urlencode(polluted)))
            r = client.get(mutated)
            if r is None:
                continue
            r_len = len(r.text or "")
            len_delta = abs(r_len - base_avg)

            status_changed = r.status_code != base_a.status_code
            length_threshold = max(150, jitter * 3 + 80)
            length_changed = len_delta >= length_threshold
            if not (status_changed or length_changed):
                continue

            proof = ValidationProof(
                method="jitter-aware-baseline",
                confirmed=True,
                steps=[
                    f"Baseline 2x: status {base_a.status_code}, len {len_a}/{len_b} "
                    f"(jitter natural {jitter} byte).",
                    f"Polluted: status {r.status_code}, len {r_len} "
                    f"(|delta| dari baseline avg = {len_delta:.0f}).",
                    f"Threshold: status berubah ATAU |delta| >= {length_threshold:.0f} byte "
                    f"(3x jitter + 80).",
                ],
                samples=[
                    f"baseline_a={len_a} baseline_b={len_b}",
                    f"polluted={r_len}",
                ],
            )
            findings.append(Finding(
                module="hpp",
                title=f"HTTP Parameter Pollution terkonfirmasi pada `{k}`",
                severity=Severity.LOW,
                description=(
                    "Mengirim parameter dengan nama sama dua kali mengubah respons "
                    "secara signifikan dibandingkan jitter natural antar baseline. "
                    "Dapat dipakai untuk melewati validasi atau WAF."
                ),
                target=mutated,
                evidence=(
                    f"baseline {base_a.status_code}/{len_a},{len_b} "
                    f"(jitter={jitter}) -> polluted {r.status_code}/{r_len}"
                ),
                cwe="CWE-235",
                confidence="confirmed",
                urls=[mutated],
                remediation=(
                    "Normalisasi parameter ganda di server (pilih satu eksplisit), "
                    "konsisten antar layer (web server, framework)."
                ),
                extra=build_extra(proof=proof),
            ))
            break
    finally:
        client.close()
    return findings
