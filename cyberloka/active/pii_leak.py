"""Detect Indonesia-specific PII leaked in HTTP responses.

Generic version (lihat ``db_pii_leak`` untuk varian DB-leak khusus).
Strict-validation v0.10.1: emit ValidationProof + awam steps.
"""
from __future__ import annotations

import re

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

PATTERNS = [
    (re.compile(r"\b\d{16}\b"), "NIK / nomor kartu (16-digit)"),
    (re.compile(r"\b\d{2}\.\d{3}\.\d{3}\.\d-\d{3}\.\d{3}\b"), "NPWP"),
    (re.compile(r"(?<![\d+])(\+62|62|0)8\d{8,11}\b"), "Nomor HP Indonesia"),
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "Email"),
    (re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"), "Kartu kredit Visa-shape"),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary, awam_steps = get_awam("pii_leak")
    try:
        r = client.get(target.base_url)
        if r is None:
            return findings
        body = r.text or ""
        per_label: dict[str, list[str]] = {}
        for rx, label in PATTERNS:
            matches = rx.findall(body)
            if matches:
                per_label[label] = list(dict.fromkeys(
                    m if isinstance(m, str) else m[0] for m in matches
                ))[:5]
        if not per_label:
            return findings
        sensitive = any(k in per_label for k in ("NIK / nomor kartu (16-digit)", "NPWP",
                                                  "Nomor HP Indonesia",
                                                  "Kartu kredit Visa-shape"))
        if sensitive:
            proof = ValidationProof(
                method="regex+sensitive-class",
                confirmed=False,
                steps=[
                    f"GET {target.base_url} -> 200, body length={len(body)}.",
                    "Pattern PII Indonesia (NIK/NPWP/HP/CC) ditemukan di body.",
                    "CATATAN: deteksi generic - varian dump-database lebih ketat di "
                    "modul `db_pii_leak`. Confidence 'tentative' - verifikasi manual.",
                ],
                samples=[f"{k}: {', '.join(v)}" for k, v in per_label.items()],
            )
            findings.append(Finding(
                module="pii_leak",
                title="Potensi kebocoran PII di response publik",
                severity=Severity.HIGH,
                description=("Pola data pribadi (NIK/NPWP/HP/CC) ditemukan di response "
                             "halaman publik. Periksa apakah benar data nyata dan tidak "
                             "seharusnya di-public."),
                target=target.base_url,
                evidence="\n".join(f"{k}: {', '.join(v)}" for k, v in per_label.items()),
                cwe="CWE-359",
                confidence="tentative",
                remediation=("Mask PII di sisi server sebelum render (cth. "
                             "`****-****-1234`). Sesuaikan dengan UU PDP - minimisasi "
                             "data, hak akses berbasis peran."),
                extra=build_extra(
                    proof=proof,
                    awam_steps=awam_steps,
                    awam_summary=awam_summary,
                ),
            ))
    finally:
        client.close()
    return findings
