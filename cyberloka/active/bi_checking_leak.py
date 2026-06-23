"""BI Checking / Kolektibilitas Score Leak — strict-validation v0.10.4.

Mendeteksi kebocoran data skor BI Checking / kolektibilitas kredit di endpoint
publik seperti /api/credit-score, /api/customer-score, /api/slik, dll.

Validasi:
  1. Probe endpoint kandidat yang biasa memuat skor BI Checking.
  2. Cari pattern: "kolektibilitas", "lancar", "macet", "DPK", "kol_1"..kol_5.
  3. Negative-control: fetch path random, jika pattern muncul juga → skip.
  4. Double-confirm: fetch ulang endpoint, pastikan konsisten.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
    is_soft_200, looks_like_html_shell,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

BI_CHECK_PATHS = [
    "/api/credit-score", "/api/v1/credit-score",
    "/api/customer-score", "/api/v1/customer-score",
    "/api/slik", "/api/v1/slik", "/api/slik-check",
    "/api/bi-checking", "/api/v1/bi-checking",
    "/api/kolektibilitas", "/api/scoring",
    "/api/credit-check", "/api/credit-report",
    "/api/debitur", "/api/v1/debitur",
    "/api/idk", "/api/ideb",
]

BI_CHECK_PATTERNS = re.compile(
    r"\b(kolektibilitas|kol[_\-]?[1-5]|lancar|dalam[_ ]perhatian[_ ]khusus|"
    r"kurang[_ ]lancar|diragukan|macet|DPK|performing[_ ]loan|"
    r"non[_ ]performing|collectibility|credit[_\- ]score|"
    r"slik[_\- ]?result|plafond|baki[_ ]debet|outstanding)\b",
    re.IGNORECASE,
)

SENSITIVE_FIELDS = re.compile(
    r"\"(nama_debitur|nik|no_rekening|plafond|baki_debet|kol|"
    r"tanggal_macet|jenis_kredit|bank_pelapor|sisa_tenor|"
    r"credit_score|scoring_result)\"",
    re.IGNORECASE,
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Data skor kredit / BI Checking pelanggan bocor di endpoint publik — "
        "informasi ini bisa dipakai untuk social engineering atau penipuan pinjol."
    )
    awam_steps = [
        "Penyerang menemukan endpoint API terkait skor kredit di aplikasi.",
        "Tanpa login / autentikasi, penyerang mengakses endpoint tersebut.",
        "Server membalas dengan data kolektibilitas / skor kredit pelanggan.",
        "Data berisi status hutang (lancar/macet), plafond, nama debitur.",
        "Penyerang gunakan data untuk penipuan terarah atau jual di dark-web.",
    ]
    try:
        # Negative control
        ctrl_url = urljoin(
            target.base_url,
            f"/cyberloka_{secrets.token_hex(6)}_ctrl"
        )
        ctrl_resp = client.get(ctrl_url)
        ctrl_body = ""
        if ctrl_resp and ctrl_resp.status_code == 200:
            ctrl_body = ctrl_resp.text or ""

        for path in BI_CHECK_PATHS:
            url = urljoin(target.base_url, path)
            resp = client.get(url)
            if resp is None or resp.status_code != 200:
                continue
            if is_soft_200(resp):
                continue
            body = resp.text or ""
            if looks_like_html_shell(body):
                continue
            if not body or len(body) < 20:
                continue

            # Check for BI Checking patterns
            pattern_hits = BI_CHECK_PATTERNS.findall(body)
            field_hits = SENSITIVE_FIELDS.findall(body)

            if len(pattern_hits) < 2 and len(field_hits) < 1:
                continue

            # Negative control: skip if control response also has these patterns
            if ctrl_body:
                ctrl_hits = BI_CHECK_PATTERNS.findall(ctrl_body)
                if len(ctrl_hits) >= len(pattern_hits):
                    continue

            # Double confirm
            resp2 = client.get(url)
            if resp2 is None or resp2.status_code != 200:
                continue
            body2 = resp2.text or ""
            pattern_hits2 = BI_CHECK_PATTERNS.findall(body2)
            if len(pattern_hits2) < 2:
                continue

            curl_cmd = (
                f"curl -s -o /dev/null -w '%{{http_code}}' '{url}'\n"
                f"curl -s '{url}' | grep -iE 'kolektibilitas|macet|lancar|DPK|credit.score'"
            )

            proof = ValidationProof(
                method="negative-control+double-confirm+pattern-match",
                confirmed=True,
                steps=[
                    f"GET {url} → 200 OK, body length={len(body)}.",
                    f"Pattern match: {len(pattern_hits)} hit BI Checking keywords.",
                    f"Sensitive fields: {field_hits[:5]}.",
                    "Negative-control path random tidak mengandung pattern yang sama.",
                    "Double-confirm: fetch kedua konsisten.",
                ],
                samples=[f"keywords={pattern_hits[:5]}", f"fields={field_hits[:5]}"],
            )

            findings.append(Finding(
                module="bi_checking_leak",
                title=f"Kebocoran data BI Checking / kolektibilitas di {path}",
                severity=Severity.HIGH,
                description=(
                    f"Endpoint {url} membalas dengan data skor kredit / kolektibilitas "
                    f"tanpa autentikasi. Ditemukan {len(pattern_hits)} keyword BI Checking "
                    f"dan {len(field_hits)} field sensitif. Data ini termasuk kategori "
                    f"data pribadi spesifik (UU PDP) dan data rahasia bank (POJK)."
                ),
                target=url,
                urls=[url],
                evidence=f"patterns={pattern_hits[:5]}, fields={field_hits[:5]}",
                cwe="CWE-200",
                confidence="confirmed",
                remediation=(
                    "1. Tambahkan autentikasi (JWT/OAuth) pada endpoint credit scoring.\n"
                    "2. Implementasi RBAC — hanya role tertentu boleh akses skor kredit.\n"
                    "3. Rate-limit dan logging pada semua akses data kredit.\n"
                    "4. Comply POJK 35/2018 tentang kerahasiaan data debitur.\n"
                    "5. Mask data sensitif di response (hanya tampilkan partial)."
                ),
                references=[
                    "https://www.ojk.go.id/id/regulasi/otoritas-jasa-keuangan/peraturan-ojk/",
                    "https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022",
                ],
                extra=build_extra(
                    proof=proof,
                    awam_steps=awam_steps,
                    awam_summary=awam_summary,
                    extra={"curl_cmd": curl_cmd},
                ),
            ))
            break  # Satu finding sudah cukup per target
    finally:
        client.close()
    return findings
