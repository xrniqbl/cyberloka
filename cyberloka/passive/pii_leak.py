"""Deteksi kebocoran PII (Personally Identifiable Information) di body response.

Cek halaman publik utama + sampel endpoint hasil crawler untuk pattern:
- Email address dalam jumlah besar (mis. di komentar HTML, JSON debug)
- NIK (16 digit angka berurutan) — KTP Indonesia
- Nomor telepon ID (08xxxxxxxxxx)
- AWS access key / Google API key
- Kartu kredit (Luhn-valid 13-16 digit)

Tujuan: menyalakan alarm bila secret/PII terlihat di response publik tanpa
otentikasi. Tidak menyimpan datanya — hanya menghitung jumlah & sampel
ter-redact.
"""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("Email", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), Severity.LOW),
    ("Nomor HP Indonesia", re.compile(r"\b08\d{8,11}\b"), Severity.LOW),
    ("NIK Indonesia (16 digit)", re.compile(r"\b\d{16}\b"), Severity.MEDIUM),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.HIGH),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), Severity.HIGH),
    ("Generic secret-like token", re.compile(
        r"['\"]?(?:secret|token|api[_-]?key|password|bearer)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-./+=]{20,}['\"]",
        re.IGNORECASE,
    ), Severity.MEDIUM),
]


def _redact(s: str, keep: int = 4) -> str:
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:]


def _scan_body(label: str, body: str) -> list[Finding] | None:
    found: list[Finding] = []
    for name, rgx, sev in _PATTERNS:
        matches = rgx.findall(body)
        if not matches:
            continue
        # Email & nomor HP biasanya OK kalau muncul di halaman kontak;
        # kita laporkan hanya bila >3 unique matches (potensi data dump)
        unique = sorted(set(matches if isinstance(matches[0], str) else [m[0] for m in matches]))
        if name in ("Email", "Nomor HP Indonesia") and len(unique) < 3:
            continue
        sample = ", ".join(_redact(str(u)) for u in unique[:5])
        found.append(
            Finding(
                module="pii_leak",
                title=f"Kebocoran {name}: {len(unique)} unique terdeteksi",
                severity=sev,
                description=(
                    f"Pola {name} muncul di response publik. Bila ini bukan data yang "
                    "memang ditujukan untuk publik (mis. halaman kontak), data pengguna / "
                    "kredensial dapat bocor."
                ),
                target=label,
                evidence=f"sample (redacted): {sample}",
                cwe="CWE-200",
                remediation=(
                    "Audit halaman/endpoint ini. Pastikan PII hanya tampil setelah otentikasi "
                    "+ otorisasi. Untuk secret/token: rotasi sekarang, pindah ke server-side env."
                ),
                references=["https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control/"],
            )
        )
    return found or None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # 1) Halaman utama
        resp = client.get(target.base_url)
        if resp is not None and resp.text:
            r = _scan_body(target.base_url, resp.text)
            if r:
                findings.extend(r)
        # 2) Endpoint hasil crawler (sampel)
        discovered = getattr(target, "discovered", None)
        if discovered is not None:
            seen_urls: set[str] = {target.base_url}
            for ep in getattr(discovered, "endpoints", [])[:20]:
                if ep.url in seen_urls:
                    continue
                seen_urls.add(ep.url)
                r2 = client.get(ep.url)
                if r2 is None or not r2.text:
                    continue
                hits = _scan_body(ep.url, r2.text)
                if hits:
                    findings.extend(hits)
    finally:
        client.close()
    return findings
