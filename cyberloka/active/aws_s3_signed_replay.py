"""AWS S3 Signed URL Long Expiry — strict-validation v0.10.4.

Menemukan S3 pre-signed URLs di response/JS dengan expiry yang terlalu lama
(>24 jam). Signed URL dengan expiry panjang sama saja dengan akses publik.

Validasi:
  1. Scan response/JS untuk pattern S3 signed URL.
  2. Parse parameter X-Amz-Expires atau Expires.
  3. Jika expiry > 86400 detik (24 jam) → temuan.
  4. Double-confirm: cek apakah URL masih accessible.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, parse_qs

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

# S3 signed URL patterns (both path-style and virtual-hosted)
S3_SIGNED_RE = re.compile(
    r"https?://(?:"
    r"[a-zA-Z0-9.\-]+\.s3[.\-][a-zA-Z0-9\-]+\.amazonaws\.com|"
    r"s3[.\-][a-zA-Z0-9\-]+\.amazonaws\.com/[a-zA-Z0-9.\-]+"
    r")[^\s\"'<>]*(?:X-Amz-Signature|Signature)=[^\s\"'<>]+",
    re.IGNORECASE,
)

# Expiry threshold: 24 hours in seconds
EXPIRY_THRESHOLD = 86400

JS_PATHS = [
    "/main.js", "/app.js", "/bundle.js",
    "/static/js/main.js", "/static/js/app.js",
]


def _get_expiry_seconds(url: str) -> int | None:
    """Extract expiry duration from S3 signed URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    # V4 signature
    if "X-Amz-Expires" in params:
        try:
            return int(params["X-Amz-Expires"][0])
        except (ValueError, IndexError):
            return None
    # V2 signature (Expires is a Unix timestamp)
    if "Expires" in params:
        try:
            import time
            exp_ts = int(params["Expires"][0])
            return exp_ts - int(time.time())
        except (ValueError, IndexError):
            return None
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "S3 signed URL dengan masa berlaku sangat lama ditemukan — "
        "file ini bisa diakses siapa saja yang tahu URL-nya selama berminggu-minggu."
    )
    awam_steps = [
        "Penyerang menemukan S3 signed URL di response/JavaScript aplikasi.",
        "URL tersebut berlaku sangat lama (>24 jam, kadang berminggu-minggu).",
        "Penyerang menyimpan URL dan bisa mengakses file kapan saja.",
        "Jika URL bocor (di log, Referer, chat), siapa pun bisa download.",
        "File sensitif (dokumen, KTP, data) terekspos tanpa batas waktu.",
    ]
    try:
        signed_urls: list[tuple[str, int]] = []  # (url, expiry_seconds)

        # Scan main page
        resp = client.get(target.base_url)
        if resp and resp.status_code == 200:
            body = resp.text or ""
            for m in S3_SIGNED_RE.finditer(body):
                url = m.group(0).rstrip("\"'>;)")
                expiry = _get_expiry_seconds(url)
                if expiry and expiry > EXPIRY_THRESHOLD:
                    signed_urls.append((url, expiry))

        # Scan JS files
        for js_path in JS_PATHS:
            url = urljoin(target.base_url, js_path)
            resp = client.get(url)
            if resp and resp.status_code == 200:
                body = resp.text or ""
                for m in S3_SIGNED_RE.finditer(body):
                    surl = m.group(0).rstrip("\"'>;)")
                    expiry = _get_expiry_seconds(surl)
                    if expiry and expiry > EXPIRY_THRESHOLD:
                        signed_urls.append((surl, expiry))

        if not signed_urls:
            return findings

        # Deduplicate by bucket+key (ignore signature params)
        seen_keys: set[str] = set()
        unique_urls: list[tuple[str, int]] = []
        for surl, expiry in signed_urls:
            parsed = urlparse(surl)
            key = parsed.hostname + (parsed.path or "")
            if key in seen_keys:
                continue
            seen_keys.add(key)
            unique_urls.append((surl, expiry))

        for surl, expiry in unique_urls[:3]:
            # Double confirm: check if URL is still accessible
            resp = client.get(surl)
            if resp and resp.status_code == 200:
                hours = expiry // 3600
                days = hours // 24

                curl_cmd = (
                    f"# S3 Signed URL with long expiry ({days} days)\n"
                    f"curl -s -o /dev/null -w '%{{http_code}}' '{surl[:120]}...'"
                )

                proof = ValidationProof(
                    method="pattern-discovery+expiry-parse+accessibility-check",
                    confirmed=True,
                    steps=[
                        "S3 signed URL ditemukan di response/JS.",
                        f"X-Amz-Expires = {expiry} detik ({hours} jam / {days} hari).",
                        f"Threshold pelanggaran: >{EXPIRY_THRESHOLD}s (24 jam).",
                        f"GET signed URL → 200 OK (masih accessible).",
                    ],
                    samples=[
                        f"expiry={expiry}s ({days}d)",
                        f"url_prefix={surl[:80]}...",
                    ],
                )

                findings.append(Finding(
                    module="aws_s3_signed_replay",
                    title=f"S3 signed URL expiry terlalu lama: {days} hari",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Pre-signed S3 URL ditemukan dengan expiry {expiry} detik "
                        f"({days} hari). Best practice: max 1 jam untuk data sensitif, "
                        f"max 24 jam untuk data publik. URL yang bocor bisa diakses "
                        f"selama masa berlaku tanpa autentikasi tambahan."
                    ),
                    target=surl[:200],
                    urls=[surl[:200]],
                    evidence=f"expiry={expiry}s ({days}d), accessible=true",
                    cwe="CWE-200",
                    confidence="confirmed",
                    remediation=(
                        "1. Kurangi expiry signed URL menjadi max 1 jam untuk data sensitif.\n"
                        "2. Gunakan CloudFront signed URL/cookie untuk kontrol lebih baik.\n"
                        "3. Implementasi on-demand URL generation (buat baru setiap request).\n"
                        "4. Jangan embed signed URL di JS/HTML statis.\n"
                        "5. Enable S3 access logging untuk monitoring."
                    ),
                    references=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html",
                    ],
                    extra=build_extra(
                        proof=proof,
                        awam_steps=awam_steps,
                        awam_summary=awam_summary,
                        extra={"curl_cmd": curl_cmd, "expiry_seconds": expiry},
                    ),
                ))
                break
    finally:
        client.close()
    return findings
