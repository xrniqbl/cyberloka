"""Permissions-Policy (formerly Feature-Policy) header audit.

Header `Permissions-Policy` mengontrol fitur browser sensitif (kamera,
mikrofon, lokasi, payment-request, accelerometer, dll.) yang boleh dipakai
halaman dan iframe-nya.

Audit ini melaporkan:
    1. Header tidak ada -> default browser = SEMUA fitur diaktifkan untuk
       same-origin. Kalau halaman embed iframe pihak ketiga tanpa
       `allow=`, fitur juga aktif di iframe -> rentan jika pihak ketiga
       di-XSS.
    2. Fitur sensitif (`payment`, `geolocation`, `microphone`, `camera`,
       `usb`, `serial`, `accelerometer`, `gyroscope`, `magnetometer`,
       `bluetooth`) dibuka untuk `*` atau origin pihak ketiga yang
       mencurigakan.
    3. Header pakai sintaks lama `Feature-Policy` (deprecated) tanpa
       `Permissions-Policy` baru.

Hanya pembacaan header. Severity LOW (best-practice).
"""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

SENSITIVE = {
    "payment", "geolocation", "microphone", "camera", "usb", "serial",
    "accelerometer", "gyroscope", "magnetometer", "bluetooth", "midi",
    "hid", "screen-wake-lock", "fullscreen",
}

# Parser ringan: 'camera=(), geolocation=(self), payment=*'
DIR_RE = re.compile(r"([a-z\-]+)\s*=\s*([^,]+)")


def _parse_permissions_policy(value: str) -> dict[str, str]:
    """Return {feature: raw_allowlist}."""
    out: dict[str, str] = {}
    for m in DIR_RE.finditer(value or ""):
        out[m.group(1).strip().lower()] = m.group(2).strip()
    return out


def _is_open(allowlist: str) -> bool:
    """True kalau allowlist mengizinkan semua origin (*) atau tidak
    membatasi (`(*)`)."""
    al = allowlist.strip().strip("()").strip()
    if al == "*" or al == "":
        return True
    if "*" in al and "https://" not in al:
        return True
    return False


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url, allow_redirects=True)
        if r is None:
            return findings

        new_h = r.headers.get("Permissions-Policy", "")
        old_h = r.headers.get("Feature-Policy", "")

        if not new_h and not old_h:
            findings.append(Finding(
                module="permission_policy",
                title="Permissions-Policy / Feature-Policy tidak diset",
                severity=Severity.LOW,
                description=(
                    "Tidak ada header `Permissions-Policy` di response. "
                    "Browser akan mengizinkan semua fitur (kamera, mic, "
                    "geolokasi, payment) untuk halaman & iframe yang "
                    "di-embed. Bila ada XSS atau iframe pihak ketiga "
                    "kompromi, fitur tetap aktif."
                ),
                target=target.base_url,
                evidence="header `Permissions-Policy` & `Feature-Policy` keduanya kosong",
                cwe="CWE-732",
                confidence="confirmed",
                remediation=(
                    "Tambahkan header default-deny lalu opt-in fitur yang "
                    "memang dipakai, mis.:\n"
                    "  `Permissions-Policy: camera=(), microphone=(), "
                    "geolocation=(self), payment=(self)`"
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                ],
            ))
            return findings

        if old_h and not new_h:
            findings.append(Finding(
                module="permission_policy",
                title="Memakai header lama `Feature-Policy` (deprecated)",
                severity=Severity.LOW,
                description=(
                    "Header `Feature-Policy` sudah deprecated dan tidak "
                    "didukung browser modern penuh. Migrasi ke "
                    "`Permissions-Policy`."
                ),
                target=target.base_url,
                evidence=truncate(f"Feature-Policy: {old_h}", 160),
                cwe="CWE-732",
                confidence="confirmed",
                remediation=(
                    "Konversi nilai ke sintaks `Permissions-Policy` baru. "
                    "Lihat tabel mapping di MDN."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                ],
            ))

        # Parsed audit
        if new_h:
            parsed = _parse_permissions_policy(new_h)
            open_sensitive: list[str] = []
            for feat in SENSITIVE:
                if feat in parsed and _is_open(parsed[feat]):
                    open_sensitive.append(f"{feat}={parsed[feat]}")
                elif feat not in parsed:
                    # Fitur sensitif tidak disebut -> default = self only
                    # Itu OK, abaikan.
                    pass
            if open_sensitive:
                findings.append(Finding(
                    module="permission_policy",
                    title=f"Permissions-Policy mengizinkan {len(open_sensitive)} fitur sensitif untuk semua origin",
                    severity=Severity.MEDIUM,
                    description=(
                        "Beberapa fitur sensitif diberi izin terlalu "
                        "longgar. Kalau halaman ini di-embed di iframe "
                        "pihak ketiga (chat widget, ad), fitur tersebut "
                        "ikut diaktifkan."
                    ),
                    target=target.base_url,
                    evidence=truncate(
                        f"sensitive_open={open_sensitive}",
                        240,
                    ),
                    cwe="CWE-732",
                    confidence="confirmed",
                    remediation=(
                        "Restrict ke `(self)` atau `()` untuk fitur yang "
                        "tidak dipakai. Contoh strict default:\n"
                        "  `Permissions-Policy: accelerometer=(), camera=(), "
                        "geolocation=(self), gyroscope=(), magnetometer=(), "
                        "microphone=(), payment=(self), usb=()`"
                    ),
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                    ],
                ))
    finally:
        client.close()
    return findings
