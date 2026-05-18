"""CSV / formula injection probe on export endpoints."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

EXPORT_HINTS = re.compile(r"(export|download|csv|excel|xlsx|report|laporan)", re.I)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings
    candidates: list[str] = []
    for u in s.urls + s.param_urls:
        if EXPORT_HINTS.search(u):
            candidates.append(u)
    candidates = candidates[:5]
    if not candidates:
        return findings
    client = HttpClient(config)
    try:
        for url in candidates:
            r = client.get(url)
            if r is None:
                continue
            ctype = (r.headers.get("Content-Type") or "").lower()
            cd = r.headers.get("Content-Disposition") or ""
            if not (
                "csv" in ctype or "excel" in ctype or "spreadsheet" in ctype
                or ".csv" in cd.lower() or ".xls" in cd.lower()
            ):
                continue
            # Cek apakah ada cell yang dimulai dengan =, +, -, @, atau TAB
            body = r.text or ""
            risky_lines = []
            for i, line in enumerate(body.splitlines()[:200]):
                # cek field mulai dengan formula trigger
                for field in line.split(","):
                    field = field.strip().strip('"')
                    if field and field[0] in ("=", "+", "-", "@", "\t"):
                        risky_lines.append(f"line {i}: {line[:80]}")
                        break
            if risky_lines:
                findings.append(Finding(
                    module="csv_injection", target=url,
                    title=f"Export CSV mengandung cell yang mulai dengan formula trigger",
                    severity=Severity.MEDIUM,
                    description=("CSV yang di-export memiliki cell mulai dengan `=`, `+`, `-`, atau `@`. "
                                 "Saat dibuka di Excel, cell tersebut dieksekusi sebagai formula. "
                                 "Attacker bisa craft data dengan `=cmd|'/c calc'!A0` untuk RCE di "
                                 "komputer staff yang membuka file."),
                    evidence="\n".join(risky_lines[:5]),
                    cwe="CWE-1236",
                    remediation=("Saat generate CSV, prefix tiap cell yang mulai dengan trigger "
                                 "formula dengan `'` (apostrof) atau bungkus dalam tanda kutip. "
                                 "Sanitize field input di sisi server sebelum disimpan."),
                    references=["https://owasp.org/www-community/attacks/CSV_Injection"],
                ))
                return findings
    finally:
        client.close()
    return findings
