"""Audit kualitas Content-Security-Policy yang sudah ada.

Modul ini melengkapi `headers` (yang hanya cek ada/tidak). Bila CSP ada
tapi memuat directive lemah (`unsafe-inline`, `unsafe-eval`, `*`,
`data:` di script-src), tetap ada masalah.
"""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig


def _parse_csp(csp: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        directive = tokens[0].lower()
        out[directive] = [t for t in tokens[1:]]
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None:
            return findings
        csp_value = resp.headers.get("Content-Security-Policy", "")
        if not csp_value:
            return findings  # modul `headers` sudah handle ini
        rules = _parse_csp(csp_value)

        weaknesses: list[tuple[str, str, Severity]] = []

        script_src = rules.get("script-src", rules.get("default-src", []))
        if "'unsafe-inline'" in script_src:
            weaknesses.append((
                "script-src memuat 'unsafe-inline'",
                "Script inline bisa dieksekusi -> XSS payload tetap berjalan meski CSP ada.",
                Severity.MEDIUM,
            ))
        if "'unsafe-eval'" in script_src:
            weaknesses.append((
                "script-src memuat 'unsafe-eval'",
                "Eval & Function() boleh -> XSS yang kompleks tetap berfungsi.",
                Severity.MEDIUM,
            ))
        if "*" in script_src:
            weaknesses.append((
                "script-src wildcard '*'",
                "Script dari origin manapun diizinkan -> CSP nyaris tidak ada gunanya.",
                Severity.HIGH,
            ))
        if any(s.startswith("data:") for s in script_src):
            weaknesses.append((
                "script-src mengizinkan data: scheme",
                "Attacker bisa pakai data:text/javascript;base64,XXX untuk inject script.",
                Severity.MEDIUM,
            ))

        # frame-ancestors absen + tidak ada X-Frame-Options
        if "frame-ancestors" not in rules and not resp.headers.get("X-Frame-Options"):
            weaknesses.append((
                "frame-ancestors tidak diset & X-Frame-Options absen",
                "Halaman tetap rentan clickjacking.",
                Severity.MEDIUM,
            ))

        # object-src absent or *
        object_src = rules.get("object-src", rules.get("default-src", []))
        if not object_src or "*" in object_src or "'self'" not in object_src and "'none'" not in object_src:
            weaknesses.append((
                "object-src tidak ketat (sebaiknya 'none')",
                "Plugin (Flash/PDF) bisa diembed -> attack via plugin lama.",
                Severity.LOW,
            ))

        # report-only mode (CSP dilewati)
        if "Content-Security-Policy-Report-Only" in resp.headers:
            weaknesses.append((
                "CSP berjalan dalam mode Report-Only",
                "CSP tidak meng-enforce, hanya report. Pelanggaran tidak diblok.",
                Severity.LOW,
            ))

        for title, desc, sev in weaknesses:
            findings.append(
                Finding(
                    module="csp_audit",
                    title=f"CSP lemah: {title}",
                    severity=sev,
                    description=desc,
                    target=target.base_url,
                    evidence=f"CSP: {csp_value[:300]}",
                    remediation=(
                        "Hapus 'unsafe-inline' & 'unsafe-eval'. Pakai nonce/hash untuk script "
                        "inline yang memang perlu. Gantilah '*' dengan whitelist domain. "
                        "Set object-src 'none' dan frame-ancestors 'none'."
                    ),
                    references=[
                        "https://csp-evaluator.withgoogle.com/",
                    ],
                )
            )
    finally:
        client.close()
    return findings
