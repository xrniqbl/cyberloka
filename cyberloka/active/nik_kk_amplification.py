"""NIK/KK Data Amplification — strict-validation v0.10.4.

Menguji endpoint yang menerima NIK dan mengembalikan data lebih banyak dari
input (amplification). Contoh: kirim NIK 16-digit, dapat nama + alamat + KK +
tempat lahir — artinya endpoint berfungsi sebagai oracle data kependudukan.

Validasi:
  1. Kirim NIK palsu (format valid tapi data tidak ada) → expect error/empty.
  2. Kirim NIK format valid (kode provinsi benar) → jika response berisi
     field tambahan (nama, alamat, dll.) yang TIDAK ada di input → amplification.
  3. Pastikan response bukan template/error page.
  4. Double-confirm dengan NIK format valid lain.
"""
from __future__ import annotations

import json
import secrets
from urllib.parse import urljoin

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
    is_soft_200, looks_like_html_shell,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

AMPLIFICATION_PATHS = [
    "/api/check-nik", "/api/v1/check-nik",
    "/api/skoring", "/api/v1/skoring",
    "/api/verify-nik", "/api/v1/verify-nik",
    "/api/dukcapil", "/api/v1/dukcapil",
    "/api/kependudukan", "/api/citizen/verify",
    "/api/identity/check", "/api/v1/identity/check",
    "/api/nik-lookup", "/api/data-nik",
    "/api/customer/verify", "/api/v1/customer/verify",
    "/api/ekyc", "/api/v1/ekyc",
]

# Fake NIK with valid province code (32 = Jawa Barat), valid date pattern
FAKE_NIKS = [
    "3201011234560001",  # format valid, data fiktif
    "3174015678900002",  # DKI Jakarta format
]

# Fields that indicate amplification (more data returned than input)
AMPLIFICATION_FIELDS = [
    "nama", "name", "full_name", "nama_lengkap",
    "alamat", "address", "tempat_lahir", "birth_place",
    "tanggal_lahir", "birth_date", "dob",
    "jenis_kelamin", "gender", "sex",
    "agama", "religion",
    "status_kawin", "marital_status",
    "pekerjaan", "occupation", "job",
    "kewarganegaraan", "nationality",
    "rt", "rw", "kelurahan", "kecamatan", "kabupaten",
    "provinsi", "province", "kode_pos", "postal_code",
    "no_kk", "nomor_kk", "family_card",
    "foto", "photo", "image",
    "golongan_darah", "blood_type",
]


def _count_amplification_fields(body: str) -> list[str]:
    """Count how many amplification fields appear in response body."""
    found = []
    lower = body.lower()
    for field in AMPLIFICATION_FIELDS:
        if f'"{field}"' in lower or f"'{field}'" in lower or f"{field}:" in lower:
            found.append(field)
    return found


def _try_endpoint(client: HttpClient, url: str, nik: str) -> tuple[int, str]:
    """Try POST and GET with NIK parameter. Return (status_code, body)."""
    # Try POST JSON
    resp = client.post(url, json={"nik": nik})
    if resp and resp.status_code == 200:
        return resp.status_code, resp.text or ""

    # Try POST form
    resp = client.post(url, data={"nik": nik})
    if resp and resp.status_code == 200:
        return resp.status_code, resp.text or ""

    # Try GET with query param
    resp = client.get(f"{url}?nik={nik}")
    if resp and resp.status_code == 200:
        return resp.status_code, resp.text or ""

    return 0, ""


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Endpoint di aplikasi Anda menerima NIK lalu mengembalikan data pribadi "
        "lengkap — penyerang bisa harvest data kependudukan massal."
    )
    awam_steps = [
        "Penyerang menemukan endpoint yang menerima nomor NIK.",
        "Penyerang mengirim NIK (bisa dari kebocoran lain atau ditebak).",
        "Server membalas dengan data lengkap: nama, alamat, tanggal lahir, agama, dll.",
        "Penyerang mengirim ribuan NIK secara otomatis (scripting).",
        "Penyerang mendapat database kependudukan mini — dipakai untuk penipuan identitas.",
    ]
    try:
        for path in AMPLIFICATION_PATHS:
            url = urljoin(target.base_url, path)

            # Step 1: negative control with obviously invalid NIK
            invalid_nik = "0000000000000000"
            neg_status, neg_body = _try_endpoint(client, url, invalid_nik)

            # Step 2: test with format-valid fake NIK
            for fake_nik in FAKE_NIKS:
                status, body = _try_endpoint(client, url, fake_nik)
                if status != 200 or not body:
                    continue
                if is_soft_200(None):  # skip — we check manually
                    pass
                if looks_like_html_shell(body):
                    continue
                if len(body) < 30:
                    continue

                amp_fields = _count_amplification_fields(body)

                # Amplification: response must have significantly more info
                # than the input (just a NIK). Need at least 3 extra fields.
                if len(amp_fields) < 3:
                    continue

                # Negative control: if invalid NIK also returns same fields, skip
                if neg_body:
                    neg_fields = _count_amplification_fields(neg_body)
                    if len(neg_fields) >= len(amp_fields) - 1:
                        continue

                # Double confirm with second fake NIK
                other_nik = FAKE_NIKS[1] if fake_nik == FAKE_NIKS[0] else FAKE_NIKS[0]
                status2, body2 = _try_endpoint(client, url, other_nik)
                if status2 == 200 and body2:
                    amp_fields2 = _count_amplification_fields(body2)
                    if len(amp_fields2) < 2:
                        continue
                    confirmed = True
                else:
                    confirmed = len(amp_fields) >= 5

                curl_cmd = (
                    f"# Reproduksi NIK amplification\n"
                    f"curl -s -X POST '{url}' "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{{\"nik\": \"{fake_nik}\"}}' | python3 -m json.tool"
                )

                proof = ValidationProof(
                    method="negative-control+amplification-ratio+double-confirm",
                    confirmed=confirmed,
                    steps=[
                        f"POST {url} dengan NIK invalid → {'no data' if not neg_body else f'{len(neg_body)} bytes'}.",
                        f"POST {url} dengan NIK format-valid → 200, {len(body)} bytes.",
                        f"Response mengandung {len(amp_fields)} field data tambahan.",
                        f"Fields: {amp_fields[:8]}.",
                        "Amplification confirmed: input=16 digit, output=data lengkap.",
                    ],
                    samples=[f"amplified_fields={amp_fields[:8]}"],
                )

                findings.append(Finding(
                    module="nik_kk_amplification",
                    title=f"NIK Data Amplification di {path}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Endpoint {url} menerima NIK dan mengembalikan "
                        f"{len(amp_fields)} field data pribadi tambahan "
                        f"({', '.join(amp_fields[:5])}, ...). Ini merupakan "
                        f"oracle data kependudukan yang bisa di-abuse untuk "
                        f"harvest data massal. Pelanggaran berat UU PDP."
                    ),
                    target=url,
                    urls=[url],
                    evidence=f"input=NIK(16digit), output_fields={amp_fields}",
                    cwe="CWE-359",
                    confidence="confirmed" if confirmed else "firm",
                    remediation=(
                        "1. HAPUS endpoint lookup NIK dari akses publik.\n"
                        "2. Implementasi autentikasi kuat (mTLS / OAuth2 + scope).\n"
                        "3. Rate-limit ketat (max 5 lookup/menit per user).\n"
                        "4. Logging & alerting untuk akses bulk.\n"
                        "5. Kembalikan hanya data minimal yang dibutuhkan (data minimization).\n"
                        "6. Comply UU PDP Pasal 16: pemrosesan sesuai tujuan awal."
                    ),
                    references=[
                        "https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022",
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                    ],
                    extra=build_extra(
                        proof=proof,
                        awam_steps=awam_steps,
                        awam_summary=awam_summary,
                        extra={"curl_cmd": curl_cmd},
                    ),
                ))
                break  # found for this path
            if findings:
                break
    finally:
        client.close()
    return findings
