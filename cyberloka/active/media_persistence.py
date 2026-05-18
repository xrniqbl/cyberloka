"""Check whether deleted media stays accessible on CDN."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

# CDN khas yang sering dipakai sosmed
CDN_HINTS = re.compile(
    r"(cdn|media|images|photos|assets|uploads|static|"
    r"cloudfront|s3|googleusercontent|fbcdn|twimg|pinimg)",
    re.I,
)
MEDIA_EXT_RE = re.compile(r"\.(jpg|jpeg|png|gif|webp|mp4|mov|webm)(\?|$)", re.I)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings

    # Cari URL media di response yang ada
    media_urls = set()
    for u in s.urls:
        if MEDIA_EXT_RE.search(u):
            host = urlparse(u).netloc
            if CDN_HINTS.search(host) or CDN_HINTS.search(u):
                media_urls.add(u)
    if not media_urls:
        return findings

    client = HttpClient(config)
    leaks = []
    try:
        for url in list(media_urls)[:6]:
            r = client.head(url)
            if r is None:
                r = client.get(url)
            if r is None:
                continue
            cc = (r.headers.get("Cache-Control") or "").lower()
            cd_age = r.headers.get("Age") or ""
            # Cache panjang + tanpa expires/auth = persisten public CDN
            if r.status_code == 200 and (
                "max-age=31536000" in cc
                or "immutable" in cc
                or ("public" in cc and "private" not in cc)
            ):
                leaks.append((url, cc, cd_age))

        if leaks:
            findings.append(Finding(
                module="media_persistence",
                target=target.base_url,
                title=f"{len(leaks)} media file di CDN dengan cache panjang/permanen",
                severity=Severity.MEDIUM,
                description=(
                    "Foto/video user disimpan di CDN dengan TTL panjang "
                    "(seringnya 1 tahun atau immutable), TANPA tanda tangan "
                    "URL waktu-terbatas.\n\n"
                    "SKENARIO SERANGAN:\n"
                    "1. User upload foto sensitif (mis. KTP untuk verifikasi).\n"
                    "2. User memutuskan untuk menghapusnya dari profile.\n"
                    "3. Backend menghapus reference di database, tapi FILE FISIK "
                    "tetap di CDN.\n"
                    "4. Attacker yang punya URL CDN (bisa dapat dari arsip / "
                    "Wayback / cache browser) tetap bisa download file tsb.\n"
                    "5. Pelanggaran 'Right to be Forgotten' GDPR / UU PDP."
                ),
                evidence="\n".join(
                    f"- {u}\n  Cache-Control: {cc}\n  Age: {age}"
                    for u, cc, age in leaks[:5]
                ),
                cwe="CWE-212",
                remediation=(
                    "LANGKAH PERBAIKAN:\n"
                    "1. Saat user delete media, JUGA hapus file fisik dari CDN/S3:\n"
                    "   ```python\n"
                    "   s3.delete_object(Bucket=BUCKET, Key=media_key)\n"
                    "   cloudfront.create_invalidation(...)  # purge cache\n"
                    "   ```\n"
                    "2. Pakai SIGNED URL dengan TTL pendek (1 jam) untuk media "
                    "private. URL setelah expire = 403.\n"
                    "3. Untuk media public (avatar dll), set "
                    "`Cache-Control: public, max-age=3600` (1 jam) — bukan "
                    "1 tahun. Saat dihapus, invalidate cache CDN.\n"
                    "4. Audit S3 lifecycle: pakai `tag` untuk tandai file "
                    "yang akan dihapus + Lambda untuk purge.\n\n"
                    "VERIFIKASI:\n"
                    "1. Upload media sebagai user.\n"
                    "2. Catat URL CDN-nya.\n"
                    "3. Hapus dari profile.\n"
                    "4. Tunggu 1 menit, lalu akses URL CDN tsb.\n"
                    "5. HARUS return 403/404."
                ),
                references=[
                    "https://gdpr-info.eu/art-17-gdpr/",
                    "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Invalidation.html",
                ],
            ))
    finally:
        client.close()
    return findings
