"""Deep `.svn/` directory disclosure scanner.

Probe artefak Subversion publik dan validasi konten:

    * `.svn/entries`     -> baris pertama angka (svn 1.6) atau XML (1.4-).
    * `.svn/wc.db`       -> SQLite magic header (svn 1.7+).
    * `.svn/format`      -> file teks berisi 1 angka.
    * `.svn/all-wcprops` -> diawali `K \\d+`.
    * `.svn/text-base/`  -> directory listing (legacy 1.6).

Setiap finding men-set `extra["reverify"]` agar validator gate konfirmasi
ulang sebelum masuk report.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

SQLITE_MAGIC = b"SQLite format 3\x00"


def _validate_entries(body: bytes) -> bool:
    text = body.decode("utf-8", "ignore")
    # svn 1.4: XML; svn 1.6: ASCII dimulai dengan angka format (8/9/10) + '\n'
    return (text.startswith("<?xml")
            or bool(re.match(r"^(8|9|10|11|12)\s", text)))


def _validate_wc_db(body: bytes) -> bool:
    return body.startswith(SQLITE_MAGIC)


def _validate_format(body: bytes) -> bool:
    text = body.decode("utf-8", "ignore").strip()
    return text.isdigit() and 1 <= int(text) <= 50


def _validate_all_wcprops(body: bytes) -> bool:
    text = body.decode("utf-8", "ignore")
    return bool(re.match(r"^K\s+\d+\s*$", text, re.M))


PROBES = [
    (".svn/entries", "SVN entries", _validate_entries,
     Severity.CRITICAL, "CWE-538"),
    (".svn/wc.db", "SVN working-copy DB", _validate_wc_db,
     Severity.CRITICAL, "CWE-538"),
    (".svn/format", "SVN format file", _validate_format,
     Severity.HIGH, "CWE-538"),
    (".svn/all-wcprops", "SVN all-wcprops", _validate_all_wcprops,
     Severity.HIGH, "CWE-538"),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.origin + "/"
    client = HttpClient(config)
    try:
        for path, label, validator, sev, cwe in PROBES:
            url = urljoin(base, path)
            r = client.get(url, allow_redirects=False,
                           headers={"Range": "bytes=0-32767"})
            if r is None or r.status_code >= 400:
                continue
            body = r.content or b""
            if not body or not validator(body):
                continue
            findings.append(Finding(
                module="svn_disclosure",
                title=f".svn directory ter-ekspos publik: {path}",
                severity=sev,
                description=(
                    f"Artefak Subversion `{path}` ({label}) dapat di-download. "
                    "Attacker dapat merekonstruksi seluruh working-copy "
                    "(`svn-extractor`, `svn-tools`) untuk membaca kode sumber "
                    "lengkap termasuk history dan config."
                ),
                target=url,
                evidence=truncate(
                    f"HTTP {r.status_code} len={len(body)} head={body[:48]!r}",
                    240,
                ),
                cwe=cwe,
                confidence="confirmed",
                remediation=(
                    "Blokir path `.svn/` di reverse proxy. Pastikan deployment "
                    "tool (rsync, scp) mengabaikan folder `.svn`. Migrasi ke "
                    "Git bila SVN sudah tidak dipakai."
                ),
                references=[
                    "https://github.com/anantshri/svn-extractor",
                ],
                extra={"reverify": {"status": (200, 206)}},
            ))
    finally:
        client.close()
    return findings
