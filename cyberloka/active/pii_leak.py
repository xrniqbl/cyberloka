"""Detect Indonesia-specific PII leaked in HTTP responses."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

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
    try:
        r = client.get(target.base_url)
        if r is None:
            return findings
        body = r.text or ""
        # Skip noise: skor: minimum 2 PII jenis berbeda, atau 3 instance.
        per_label: dict[str, list[str]] = {}
        for rx, label in PATTERNS:
            matches = rx.findall(body)
            if matches:
                per_label[label] = list(dict.fromkeys(
                    m if isinstance(m, str) else m[0] for m in matches
                ))[:5]
        if not per_label:
            return findings
        # Email saja umumnya OK (footer kontak), jadi naikkan severity hanya kalau
        # ada NIK/NPWP/HP/CC.
        sensitive = any(k in per_label for k in ("NIK / nomor kartu (16-digit)", "NPWP",
                                                  "Nomor HP Indonesia",
                                                  "Kartu kredit Visa-shape"))
        if sensitive:
            findings.append(Finding(
                module="pii_leak",
                title="Potensi kebocoran PII di response publik",
                severity=Severity.HIGH,
                description=("Pola data pribadi (NIK/NPWP/HP/CC) ditemukan di response "
                             "halaman publik. Periksa apakah benar data nyata dan tidak "
                             "seharusnya di-public."),
                target=target.base_url,
                evidence="\n".join(f"{k}: {', '.join(v)}" for k, v in per_label.items()),
                cwe="CWE-359", confidence="tentative",
                remediation=("Mask PII di sisi server sebelum render (cth. "
                             "`****-****-1234`). Sesuaikan dengan UU PDP — minimisasi "
                             "data, hak akses berbasis peran."),
            ))
    finally:
        client.close()
    return findings
