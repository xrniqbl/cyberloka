"""macOS `.DS_Store` exposure scanner.

`.DS_Store` adalah file metadata yang dibuat Finder macOS di setiap folder
yang pernah dibuka. Bila ter-deploy ke webroot, file ini berisi *daftar
nama file* di folder tersebut — bocoran path yang amat berguna untuk
attacker melakukan content discovery.

Probe:
    /.DS_Store, /assets/.DS_Store, /static/.DS_Store, /uploads/.DS_Store,
    /admin/.DS_Store, /backup/.DS_Store, /images/.DS_Store, /js/.DS_Store

Validasi:
    * Magic byte `\\x00\\x00\\x00\\x01Bud1` di offset 0.
    * Ukuran file >= 4096 byte (DS_Store kosong = 0/120 byte; tanpa
      konten berarti).

Decoder ringan ekstrak nama-nama file yang terdaftar (string ASCII di
record buddy-tree) untuk dimasukkan ke evidence.
"""
from __future__ import annotations

import re
import struct
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

DS_MAGIC = b"\x00\x00\x00\x01Bud1"

PATHS = [
    ".DS_Store", "assets/.DS_Store", "static/.DS_Store", "uploads/.DS_Store",
    "admin/.DS_Store", "backup/.DS_Store", "images/.DS_Store", "img/.DS_Store",
    "js/.DS_Store", "css/.DS_Store", "files/.DS_Store", "media/.DS_Store",
    "public/.DS_Store", "data/.DS_Store", "docs/.DS_Store",
]


def _decode_filenames(body: bytes, max_n: int = 25) -> list[str]:
    """Heuristik: cari sekuens UTF-16-BE atau ASCII printable di body
    (DS_Store menyimpan nama file sebagai UTF-16BE prefix-length).
    Bukan parser akurat tapi cukup untuk evidence."""
    out: list[str] = []
    seen: set[str] = set()
    # Cara 1: UTF-16BE: setiap nama diawali 4-byte panjang, lalu chars 16-bit BE.
    i = 0
    n = len(body)
    while i < n - 8 and len(out) < max_n:
        try:
            length = struct.unpack(">I", body[i:i + 4])[0]
        except struct.error:
            break
        if 1 <= length <= 64 and i + 4 + length * 2 <= n:
            chunk = body[i + 4:i + 4 + length * 2]
            try:
                s = chunk.decode("utf-16-be", errors="strict")
            except UnicodeDecodeError:
                s = ""
            if s and re.match(r"^[\w.\-\s]{1,64}$", s):
                if s not in seen:
                    seen.add(s); out.append(s)
                i += 4 + length * 2
                continue
        i += 1
    # Fallback: scan strings
    if not out:
        for m in re.finditer(rb"[A-Za-z0-9._\-]{4,32}", body):
            s = m.group(0).decode("ascii", "ignore")
            # Filter struct/internal markers
            if s in ("Bud1", "DSDB", "moDD", "modDateD", "lg1Sblob"):
                continue
            if s not in seen:
                seen.add(s); out.append(s)
                if len(out) >= max_n:
                    break
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.origin + "/"
    client = HttpClient(config)
    found: set[str] = set()
    try:
        for path in PATHS:
            url = urljoin(base, path)
            if url in found:
                continue
            r = client.get(url, allow_redirects=False,
                           headers={"Range": "bytes=0-65535"})
            if r is None or r.status_code >= 400:
                continue
            body = r.content or b""
            if not body.startswith(DS_MAGIC):
                continue
            if len(body) < 200:
                continue  # DS_Store kosong/aneh -> skip
            found.add(url)
            names = _decode_filenames(body)
            findings.append(Finding(
                module="ds_store_leak",
                title=f".DS_Store ter-ekspos: {path}",
                severity=Severity.MEDIUM if names else Severity.LOW,
                description=(
                    "File metadata Finder macOS terbawa ke server publik. "
                    "Isinya membocorkan nama-nama file yang ada di folder "
                    "tersebut, sangat membantu attacker untuk content "
                    "discovery (mis. menemukan backup.sql, .env.bak, dll)."
                ),
                target=url,
                evidence=truncate(
                    f"HTTP {r.status_code}, magic=Bud1, len={len(body)}, "
                    f"file_names_extracted={names[:15]}",
                    280,
                ),
                cwe="CWE-538",
                confidence="confirmed",
                remediation=(
                    "1) Hapus semua file `.DS_Store` dari webroot: "
                    "`find . -name .DS_Store -delete`. "
                    "2) Tambah `.DS_Store` ke `.gitignore` & deployment "
                    "ignore-list. "
                    "3) Block di reverse proxy: nginx "
                    "`location ~ /\\.DS_Store { return 404; }`."
                ),
                references=[
                    "https://0day.work/parsing-the-ds_store-file-format/",
                ],
                extra={"reverify": {"status": (200, 206)}},
            ))
    finally:
        client.close()
    return findings
