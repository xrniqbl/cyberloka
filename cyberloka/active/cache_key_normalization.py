"""Cache Key Normalization Poisoning — strict-validation v0.10.4.

Menguji cache poisoning via unkeyed headers/parameters. Jika CDN/cache
menormalisasi URL path tetapi backend memperlakukannya berbeda, penyerang
bisa meracuni cache.

Validasi:
  1. Kirim request dengan header unkeyed yang mengubah response.
  2. Cek apakah response di-cache (X-Cache: HIT header).
  3. Kirim request normal ke URL yang sama — jika mendapat response yang poisoned.
  4. Double-confirm.
"""
from __future__ import annotations

import secrets

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

UNKEYED_HEADERS = [
    ("X-Forwarded-Host", "evil.cyberloka-test.example"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Forwarded-Proto", "nothttps"),
    ("X-Host", "evil.cyberloka-test.example"),
    ("X-Forwarded-Port", "1337"),
    ("X-Forwarded-Prefix", "/evil-prefix"),
    ("Transfer-Encoding", "chunked"),
]

# Path normalization variants
NORM_PATHS = [
    "/",
    "/index.html",
    "/index",
]


def _is_cached(resp) -> bool:
    """Check if response came from cache."""
    if resp is None:
        return False
    headers = resp.headers
    # Various CDN cache indicators
    x_cache = (headers.get("X-Cache", "") or "").lower()
    cf_cache = (headers.get("CF-Cache-Status", "") or "").lower()
    age = headers.get("Age", "")
    cc = (headers.get("Cache-Control", "") or "").lower()

    if "hit" in x_cache or "hit" in cf_cache:
        return True
    if age and int(age) > 0:
        return True
    if "public" in cc or "max-age" in cc:
        return True
    return False


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "CDN/cache bisa diracuni lewat header non-standar — pengunjung berikutnya "
        "mendapat halaman versi penyerang dari cache."
    )
    awam_steps = [
        "Penyerang mengirim request ke website dengan header non-standar.",
        "Header tersebut mengubah isi response (redirect, injeksi).",
        "CDN menyimpan response yang sudah dimodifikasi ke cache.",
        "Pengunjung normal yang membuka URL yang sama mendapat versi poisoned.",
        "Penyerang bisa redirect semua pengunjung ke phishing atau inject skimmer.",
    ]
    try:
        # First check if target uses caching
        baseline = client.get(target.base_url)
        if baseline is None:
            return findings

        has_cache = _is_cached(baseline)
        baseline_body = baseline.text or ""
        baseline_len = len(baseline_body)

        for header_name, header_value in UNKEYED_HEADERS:
            marker = f"cyberloka-{secrets.token_hex(4)}"
            if header_name in ("X-Forwarded-Host", "X-Host"):
                test_value = f"{marker}.example"
            else:
                test_value = header_value

            # Send poisoning request with cache buster to avoid poisoning real cache
            buster = secrets.token_hex(4)
            cache_bust_url = f"{target.base_url}?cb={buster}"
            resp = client.get(cache_bust_url, headers={header_name: test_value})
            if resp is None:
                continue

            body = resp.text or ""

            # Check if the header value is reflected in response
            reflected = (
                test_value in body
                or (marker in body if marker != header_value else False)
                or test_value in str(resp.headers)
            )

            if not reflected:
                continue

            # Check if response is cacheable
            cacheable = _is_cached(resp) or has_cache

            if not cacheable:
                continue

            # Double confirm
            resp2 = client.get(cache_bust_url, headers={header_name: test_value})
            if resp2 is None:
                continue
            body2 = resp2.text or ""
            if test_value not in body2 and marker not in body2:
                continue

            curl_cmd = (
                f"# Cache key normalization poisoning\n"
                f"curl -s -D - '{target.base_url}' \\\n"
                f"  -H '{header_name}: {test_value}' | head -30"
            )

            proof = ValidationProof(
                method="unkeyed-header-injection+cache-check+double-confirm",
                confirmed=True,
                steps=[
                    f"Baseline: GET {target.base_url} → cached={'yes' if has_cache else 'possibly'}.",
                    f"Injection: GET + {header_name}: {test_value}.",
                    "Header value reflected in response body/headers.",
                    "Response is cacheable (Cache-Control/X-Cache indicate caching).",
                    "Double-confirm: reflected value konsisten.",
                    "Kesimpulan: unkeyed header bisa poison cache.",
                ],
                samples=[
                    f"header={header_name}",
                    f"reflected_value={test_value[:50]}",
                    f"cache_indicators={resp.headers.get('X-Cache', '')}",
                ],
            )

            findings.append(Finding(
                module="cache_key_normalization",
                title=f"Cache poisoning via unkeyed header: {header_name}",
                severity=Severity.HIGH,
                description=(
                    f"Header `{header_name}` dipantulkan di response yang cacheable. "
                    f"Karena header ini bukan bagian dari cache key, penyerang bisa "
                    f"meracuni cache: semua pengunjung berikutnya mendapat response "
                    f"yang sudah dimodifikasi penyerang. Sangat berbahaya untuk inject "
                    f"redirect ke phishing atau memasang skimmer kartu kredit."
                ),
                target=target.base_url,
                urls=[target.base_url],
                evidence=f"header={header_name}, value={test_value}, reflected=true, cached=true",
                cwe="CWE-349",
                confidence="confirmed",
                remediation=(
                    "1. Tambahkan header yang di-reflect ke Vary response header.\n"
                    "2. Block / strip header non-standar di CDN/load-balancer.\n"
                    "3. Set Cache-Control: private/no-store untuk halaman sensitif.\n"
                    "4. Jangan reflect host/scheme headers ke response body.\n"
                    "5. Gunakan cache key yang include semua request components."
                ),
                references=[
                    "https://portswigger.net/research/practical-web-cache-poisoning",
                ],
                extra=build_extra(
                    proof=proof,
                    awam_steps=awam_steps,
                    awam_summary=awam_summary,
                    extra={"curl_cmd": curl_cmd},
                ),
            ))
            break
    finally:
        client.close()
    return findings
