"""Azure SAS Token Leak — strict-validation v0.10.4.

Menemukan Azure Shared Access Signature (SAS) tokens di responses/JS.
SAS token yang bocor memberikan akses langsung ke Azure Blob Storage.

Validasi:
  1. Scan response/JS untuk pattern SAS token.
  2. Parse permission dan expiry.
  3. Jika permission terlalu luas atau expiry terlalu lama → temuan.
  4. Double-confirm: cek apakah resource accessible.
"""
from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

# Azure SAS token pattern
# Contains sig= and (sv= or se= or sp=)
AZURE_SAS_RE = re.compile(
    r"https?://[a-zA-Z0-9\-]+\.blob\.core\.windows\.net/[^\s\"'<>]*"
    r"(?:sig=[A-Za-z0-9%+/=]+)[^\s\"'<>]*",
    re.IGNORECASE,
)

# Also look for SAS tokens in query params
SAS_PARAM_RE = re.compile(
    r"(?:sv=\d{4}-\d{2}-\d{2}).*?(?:sig=[A-Za-z0-9%+/=]{20,})",
    re.IGNORECASE,
)

JS_PATHS = [
    "/main.js", "/app.js", "/bundle.js",
    "/static/js/main.js", "/static/js/app.js",
]


def _parse_sas_params(url: str) -> dict:
    """Parse SAS token parameters."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    result = {}
    if "sp" in params:
        result["permissions"] = params["sp"][0]
    if "se" in params:
        result["expiry"] = params["se"][0]
    if "sv" in params:
        result["version"] = params["sv"][0]
    if "sig" in params:
        result["signature"] = params["sig"][0][:20] + "..."
    return result


def _is_overly_permissive(permissions: str) -> bool:
    """Check if SAS permissions are too broad."""
    # r=read, w=write, d=delete, l=list, a=add, c=create
    dangerous = set("wdlac")
    return bool(dangerous & set(permissions.lower()))


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Token akses Azure Storage (SAS) ditemukan di halaman publik — "
        "siapa pun bisa mengakses, bahkan menulis, ke storage Anda."
    )
    awam_steps = [
        "Penyerang menemukan SAS token di source code JavaScript atau response API.",
        "SAS token berisi permission untuk baca/tulis/hapus file di Azure Storage.",
        "Penyerang menggunakan token tersebut untuk mengakses blob container.",
        "Penyerang bisa download seluruh isi storage atau upload file berbahaya.",
        "Data pelanggan, backup, dan dokumen internal bocor.",
    ]
    try:
        sas_urls: list[str] = []

        # Scan main page
        resp = client.get(target.base_url)
        if resp and resp.status_code == 200:
            body = resp.text or ""
            for m in AZURE_SAS_RE.finditer(body):
                sas_urls.append(m.group(0).rstrip("\"'>;)"))

        # Scan JS files
        for js_path in JS_PATHS:
            url = urljoin(target.base_url, js_path)
            resp = client.get(url)
            if resp and resp.status_code == 200:
                body = resp.text or ""
                for m in AZURE_SAS_RE.finditer(body):
                    sas_urls.append(m.group(0).rstrip("\"'>;)"))

        if not sas_urls:
            return findings

        # Deduplicate
        seen: set[str] = set()
        unique_urls: list[str] = []
        for surl in sas_urls:
            sig = parse_qs(urlparse(surl).query).get("sig", [""])[0]
            if sig in seen:
                continue
            seen.add(sig)
            unique_urls.append(surl)

        for sas_url in unique_urls[:3]:
            sas_params = _parse_sas_params(sas_url)
            permissions = sas_params.get("permissions", "r")
            expiry = sas_params.get("expiry", "")
            overly_permissive = _is_overly_permissive(permissions)

            # Double confirm: test if SAS URL is accessible
            resp = client.get(sas_url)
            if resp is None:
                continue
            if resp.status_code in (403, 401, 404):
                continue  # Token expired or invalid

            if resp.status_code in (200, 206):
                severity = Severity.HIGH if overly_permissive else Severity.MEDIUM

                curl_cmd = (
                    f"# Azure SAS token leak\n"
                    f"curl -s -o /dev/null -w '%{{http_code}}' '{sas_url[:150]}...'"
                )

                proof = ValidationProof(
                    method="sas-pattern-discovery+permission-check+accessibility-test",
                    confirmed=True,
                    steps=[
                        "Azure SAS URL ditemukan di response/JS.",
                        f"Permissions: {permissions} ({'OVERLY PERMISSIVE' if overly_permissive else 'read-only'}).",
                        f"Expiry: {expiry or 'unknown'}.",
                        f"GET SAS URL → {resp.status_code} (accessible).",
                    ],
                    samples=[
                        f"permissions={permissions}",
                        f"expiry={expiry}",
                        f"url_prefix={sas_url[:80]}...",
                    ],
                )

                findings.append(Finding(
                    module="azure_sas_leak",
                    title=f"Azure SAS token bocor di response {'(write access!)' if overly_permissive else ''}",
                    severity=severity,
                    description=(
                        f"Azure Blob Storage SAS token ditemukan di halaman publik. "
                        f"Token permissions: {permissions}. "
                        f"{'Token memberikan akses WRITE/DELETE — sangat berbahaya. ' if overly_permissive else ''}"
                        f"Siapa pun yang melihat source code bisa mengakses storage."
                    ),
                    target=sas_url[:200],
                    urls=[sas_url[:200]],
                    evidence=f"permissions={permissions}, expiry={expiry}, status={resp.status_code}",
                    cwe="CWE-200",
                    confidence="confirmed",
                    remediation=(
                        "1. JANGAN embed SAS token di frontend/JS.\n"
                        "2. Generate SAS token on-demand via backend dengan expiry pendek.\n"
                        "3. Gunakan User Delegation SAS (lebih aman dari Account SAS).\n"
                        "4. Terapkan principle of least privilege pada permissions.\n"
                        "5. Revoke/rotate SAS token yang bocor SEGERA.\n"
                        "6. Enable Azure Storage analytics logging."
                    ),
                    references=[
                        "https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview",
                    ],
                    extra=build_extra(
                        proof=proof,
                        awam_steps=awam_steps,
                        awam_summary=awam_summary,
                        extra={"curl_cmd": curl_cmd, "permissions": permissions},
                    ),
                ))
                break
    finally:
        client.close()
    return findings
