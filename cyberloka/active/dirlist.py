"""Directory listing exposure check - 9 server signature + skip SPA echo.

Tidak hanya cek 'Index of /' (Apache); ditambahkan signature untuk
Tomcat, IIS, Lighttpd, Caddy, Nginx autoindex, Python http.server, dsb.
Kandidat path yang membalikkan respons identik dengan homepage di-skip
(SPA catch-all).
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

CANDIDATE_DIRS = [
    "/", "/uploads/", "/files/", "/static/", "/assets/", "/images/", "/img/",
    "/backup/", "/old/", "/tmp/", "/private/", "/data/", "/logs/", "/docs/",
    "/test/", "/upload/", "/media/", "/user/",
]
DIRLIST_SIGNATURES = [
    re.compile(r"<title>\s*Index of\s+/", re.I),
    re.compile(r"<h1>\s*Index of\s+/", re.I),
    re.compile(r"Directory listing for ", re.I),
    re.compile(r"<title>\s*Directory listing\s+for", re.I),
    re.compile(r"<title>\s*Directory:", re.I),
    re.compile(r'<pre>\s*<a href="\.\./">\.\./</a>', re.I),
    re.compile(r"<h2>--- Directory listing for", re.I),
]


def _is_dirlisting(text: str) -> bool:
    return any(rx.search(text or "") for rx in DIRLIST_SIGNATURES)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        home = client.get(target.origin + "/", allow_redirects=True)
        home_hash = (
            hashlib.sha1((home.text or "").encode("utf-8", "ignore")).hexdigest()
            if home is not None
            else ""
        )
        seen: set[str] = set()
        for d in CANDIDATE_DIRS:
            url = urljoin(target.origin + "/", d.lstrip("/"))
            if url in seen:
                continue
            resp = client.get(url, allow_redirects=False)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if home_hash and hashlib.sha1(body.encode("utf-8", "ignore")).hexdigest() == home_hash:
                continue
            if not _is_dirlisting(body):
                continue
            findings.append(
                Finding(
                    module="dirlist",
                    title=f"Directory listing aktif: {url}",
                    severity=Severity.MEDIUM,
                    description=(
                        "Server menampilkan daftar isi direktori. Attacker dapat menelusuri "
                        "file untuk mencari konfigurasi/backup/upload yang tidak seharusnya publik."
                    ),
                    target=url,
                    evidence=f"signature match in {url}",
                    cwe="CWE-548",
                    confidence="confirmed",
                    urls=[url],
                    remediation=(
                        "Matikan autoindex / directory listing di web server "
                        "(`autoindex off` di Nginx, `Options -Indexes` di Apache, hapus "
                        "`directory-browsing` di IIS). Bila perlu listing, lindungi dengan auth."
                    ),
                    references=["https://cwe.mitre.org/data/definitions/548.html"],
                )
            )
            seen.add(url)
    finally:
        client.close()
    return findings
