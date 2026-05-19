"""AWS Lambda Function URL Open Access — strict-validation v0.10.4.

Menemukan Lambda Function URLs di JavaScript/response dan menguji apakah
bisa diakses tanpa IAM auth (AuthType: NONE).

Validasi:
  1. Scan JS/HTML untuk Lambda Function URL patterns.
  2. Probe URL tersebut tanpa auth header.
  3. Jika response valid (bukan 403/401) → open access.
  4. Negative control: cek apakah ada IAM enforcement.
  5. Double-confirm.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
    is_soft_200,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

# Lambda Function URL pattern: https://<url-id>.lambda-url.<region>.on.aws/
LAMBDA_URL_RE = re.compile(
    r"https?://[a-z0-9]{20,}\.lambda-url\.[a-z0-9\-]+\.on\.aws/?[^\s\"'<>]*",
    re.IGNORECASE,
)

# Also check for API Gateway Lambda integration (less specific but common)
APIGW_LAMBDA_RE = re.compile(
    r"https?://[a-z0-9]+\.execute-api\.[a-z0-9\-]+\.amazonaws\.com/[^\s\"'<>]*",
    re.IGNORECASE,
)

JS_PATHS = [
    "/main.js", "/app.js", "/bundle.js",
    "/static/js/main.js", "/static/js/app.js",
    "/_next/static/chunks/app.js",
    "/assets/index.js", "/dist/main.js",
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Lambda Function URL Anda bisa diakses tanpa autentikasi IAM — "
        "siapa pun di internet bisa memanggil fungsi tersebut."
    )
    awam_steps = [
        "Penyerang menemukan URL Lambda Function di source code JavaScript.",
        "Penyerang memanggil URL tersebut langsung dari browser/curl.",
        "Karena AuthType=NONE, server tidak meminta autentikasi.",
        "Lambda function mengeksekusi dan mengembalikan data/aksi.",
        "Penyerang bisa abuse fungsi tersebut (baca data, trigger aksi, DDoS).",
    ]
    try:
        lambda_urls: set[str] = set()

        # Scan main page
        resp = client.get(target.base_url)
        if resp and resp.status_code == 200:
            body = resp.text or ""
            for m in LAMBDA_URL_RE.finditer(body):
                lambda_urls.add(m.group(0).rstrip("\"'>;)"))

        # Scan JS files
        for js_path in JS_PATHS:
            url = urljoin(target.base_url, js_path)
            resp = client.get(url)
            if resp and resp.status_code == 200:
                body = resp.text or ""
                for m in LAMBDA_URL_RE.finditer(body):
                    lambda_urls.add(m.group(0).rstrip("\"'>;)"))

        if not lambda_urls:
            return findings

        # Test each Lambda URL for open access
        for lurl in list(lambda_urls)[:5]:
            # Strip trailing path fragments
            clean_url = lurl.split("?")[0].rstrip("/")
            resp = client.get(clean_url)
            if resp is None:
                continue

            # IAM-enforced Lambda URLs return 403 with specific message
            if resp.status_code == 403:
                body = (resp.text or "").lower()
                if "forbidden" in body or "accessdenied" in body:
                    continue  # IAM enforced — good

            if resp.status_code in (401, 403):
                continue

            # If we get a successful response (200, or even 400/500 with data)
            if resp.status_code in (200, 201, 204, 400, 500):
                body = resp.text or ""
                if resp.status_code in (200, 201, 204) and len(body) > 0:
                    # Double confirm
                    resp2 = client.get(clean_url)
                    if resp2 is None or resp2.status_code in (401, 403):
                        continue

                    curl_cmd = (
                        f"# Lambda Function URL — open access (no IAM)\n"
                        f"curl -s '{clean_url}'"
                    )

                    proof = ValidationProof(
                        method="lambda-url-discovery+no-auth-probe+double-confirm",
                        confirmed=True,
                        steps=[
                            f"Lambda Function URL ditemukan di JS/HTML target.",
                            f"GET {clean_url} → {resp.status_code} (tanpa Authorization header).",
                            "Response bukan 403/401 → AuthType bukan AWS_IAM.",
                            f"Double-confirm: {resp2.status_code} — konsisten.",
                            "Kesimpulan: Lambda Function URL accessible tanpa IAM.",
                        ],
                        samples=[
                            f"url={clean_url}",
                            f"status={resp.status_code}",
                            f"body_snippet={body[:80]}",
                        ],
                    )

                    findings.append(Finding(
                        module="aws_lambda_url_open",
                        title=f"AWS Lambda Function URL terbuka tanpa IAM auth",
                        severity=Severity.HIGH,
                        description=(
                            f"Lambda Function URL {clean_url} bisa diakses tanpa "
                            f"autentikasi IAM (AuthType: NONE). Fungsi ini merespons "
                            f"dengan status {resp.status_code}. Tanpa kontrol akses, "
                            f"siapa pun bisa invoke fungsi ini — risiko data leak, "
                            f"DDoS, atau aksi yang tidak diinginkan."
                        ),
                        target=clean_url,
                        urls=[clean_url],
                        evidence=f"lambda_url={clean_url}, status={resp.status_code}, no_iam=true",
                        cwe="CWE-306",
                        confidence="confirmed",
                        remediation=(
                            "1. Set AuthType=AWS_IAM pada Lambda Function URL.\n"
                            "2. Jika perlu publik, tambahkan custom auth (JWT/API key) di function code.\n"
                            "3. Implementasi rate limiting via reserved concurrency.\n"
                            "4. Tambahkan WAF di depan Lambda URL (via CloudFront).\n"
                            "5. Jangan expose Lambda URL di frontend JS — gunakan API Gateway."
                        ),
                        references=[
                            "https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html",
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
