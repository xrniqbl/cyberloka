"""EXIF metadata leak in profile photos / posts."""
from __future__ import annotations

import re
import struct
from urllib.parse import urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

JPEG_RE = re.compile(r"https?://[^\s\"'<>]+?\.(jpe?g|JPE?G)(\?[^\s\"'<>]*)?")


def _has_exif(content: bytes) -> tuple[bool, dict]:
    """Best-effort EXIF detection without PIL.

    JPEG: SOI (FFD8) + APP1 marker (FFE1) + 'Exif\\0\\0'
    Returns (has_exif, summary_dict).
    """
    if len(content) < 20:
        return False, {}
    if content[:2] != b"\xff\xd8":
        return False, {}
    pos = 2
    has = False
    info = {}
    while pos < min(len(content), 60000):
        if content[pos] != 0xFF:
            break
        marker = content[pos + 1]
        if marker == 0xDA:  # SOS — start of scan, EXIF section sebelumnya
            break
        size = struct.unpack(">H", content[pos + 2 : pos + 4])[0]
        segment = content[pos + 4 : pos + 2 + size]
        if marker == 0xE1 and segment[:6] == b"Exif\x00\x00":
            has = True
            # Cari pola GPS / Make / Model dalam EXIF blob
            blob = segment.lower()
            if b"gps" in blob:
                info["GPS data"] = "PRESENT"
            for key in (b"make", b"model", b"datetime", b"software"):
                if key in blob:
                    info[key.decode()] = "found"
            break
        pos += 2 + size
    return has, info


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings

    candidates = set()
    client = HttpClient(config)
    try:
        # Cari URL JPEG di halaman utama + halaman profile/post
        for url in [target.base_url] + s.urls[:8]:
            r = client.get(url)
            if r is None:
                continue
            for m in JPEG_RE.finditer(r.text or ""):
                candidates.add(m.group(0))
                if len(candidates) >= 6:
                    break
            if len(candidates) >= 6:
                break

        leaks = []
        for img_url in list(candidates)[:5]:
            r = client.get(img_url)
            if r is None or r.status_code != 200:
                continue
            ctype = (r.headers.get("Content-Type") or "").lower()
            if "jpeg" not in ctype and "jpg" not in ctype:
                continue
            content = r.content[:65000]
            has, info = _has_exif(content)
            if has:
                leaks.append((img_url, info))

        if leaks:
            has_gps = any("GPS data" in info for _, info in leaks)
            sev = Severity.HIGH if has_gps else Severity.MEDIUM
            findings.append(Finding(
                module="exif_leak",
                target=target.base_url,
                title=(
                    f"{len(leaks)} foto publik mengandung metadata EXIF"
                    + (" termasuk GPS" if has_gps else "")
                ),
                severity=sev,
                description=(
                    "Foto profile/post yang publik masih membawa metadata EXIF: "
                    "GPS koordinat, model kamera/HP, tanggal-jam tepat, software "
                    "edit.\n\n"
                    "SKENARIO SERANGAN:\n"
                    "1. Korban upload foto dari HP-nya (default semua HP simpan "
                    "GPS di EXIF).\n"
                    "2. Stalker download foto profile via klik kanan → save.\n"
                    "3. Stalker pakai tool seperti `exiftool` untuk extract "
                    "lat/long → titik di Google Maps = rumah korban.\n"
                    "4. Cocok untuk kasus KDRT, intimidasi, doxxing.\n"
                    "5. Bahkan tanpa GPS, info kamera + jam upload bisa dipakai "
                    "untuk membuktikan korban berada di lokasi tertentu."
                ),
                evidence="\n".join(
                    f"- {u}\n  EXIF: {', '.join(f'{k}={v}' for k, v in info.items())}"
                    for u, info in leaks[:5]
                ),
                cwe="CWE-200",
                remediation=(
                    "LANGKAH PERBAIKAN:\n"
                    "1. Saat upload, STRIP EXIF di server SEBELUM disimpan ke S3:\n"
                    "   ```python\n"
                    "   from PIL import Image\n"
                    "   img = Image.open(file)\n"
                    "   img.save(out, exif=b'')  # blank EXIF\n"
                    "   ```\n"
                    "2. Atau pakai `exiftool` dari command line:\n"
                    "   `exiftool -all= -overwrite_original image.jpg`\n"
                    "3. Untuk foto yang sudah ter-upload, lakukan migration: "
                    "loop semua, strip, replace.\n"
                    "4. Convert ke WebP saat re-encode → otomatis hilang EXIF.\n"
                    "5. Edukasi user: 'foto Anda akan diproses untuk privacy'.\n\n"
                    "VERIFIKASI:\n"
                    "Download foto profile setelah patch, jalankan:\n"
                    "  `exiftool downloaded.jpg | grep -i gps`\n"
                    "Output harus KOSONG."
                ),
                references=[
                    "https://owasp.org/www-community/Image_Privacy_Issues",
                    "https://exiftool.org/",
                ],
            ))
    finally:
        client.close()
    return findings
