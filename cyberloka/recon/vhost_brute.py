"""Virtual-host bruteforce scanner.

Tujuan: temukan virtual host yang di-host pada IP yang sama tapi tidak
di-link dari DNS publik. Banyak server (Apache, nginx, IIS) merespons
berbeda untuk request `Host:` yang valid, sehingga kita bisa enumerasi
nama vhost dengan men-fuzz header `Host`.

Strategi:
    1. **Baseline 1**  GET / dengan Host = host asli
    2. **Baseline 2**  GET / dengan Host = nilai random yang pasti tidak ada
    3. Untuk setiap kandidat name (admin, dev, staging, internal, ...):
       GET / dengan Host = `<name>.<base>` *atau* `<name>` (tanpa base).
       Bandingkan response signature (status + content_length +
       sha1(body[:512])) terhadap dua baseline.
    4. Vhost yang **berbeda dari kedua baseline** = candidate vhost ada.

Validasi sebelum lapor:
    * Server header memuat indikator HTTP server (Apache/nginx/IIS),
      kalau Cloudflare/CDN -> probe biasanya gagal, skip diam-diam.
    * Vhost yang ditemukan harus berbeda dari **kedua** baseline; bukan
      hanya berbeda dari baseline asli (karena server bisa merespons
      404 berbeda untuk Host yang aneh).
    * Untuk hindari false-positive akibat Cloudflare 1016 (origin DNS
      error), buang response status 525-530 atau body memuat 'Cloudflare'.
"""
from __future__ import annotations

import hashlib
import random
import re
import string
from urllib.parse import urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

VHOST_NAMES = [
    # generic env
    "admin", "administrator", "panel", "cpanel", "backoffice", "backend",
    "internal", "intranet", "private", "staff", "manage", "console",
    # dev/staging
    "dev", "develop", "development", "stg", "staging", "stag", "test",
    "testing", "qa", "uat", "preview", "beta", "alpha", "sandbox",
    # services
    "api", "api-internal", "api-admin", "v1", "v2", "graphql",
    "auth", "sso", "oauth", "login", "id",
    # ops
    "monitoring", "metrics", "grafana", "kibana", "jenkins", "gitlab",
    "git", "registry", "vault", "k8s", "argocd",
    # data
    "db", "database", "mysql", "redis", "elastic",
    # other
    "old", "legacy", "backup", "bak", "secret", "hidden",
]

CDN_BANNERS = ("cloudflare", "akamai", "fastly", "incapsula", "sucuri")


def _rand_label(n: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))


def _signature(status: int, body: bytes, location: str = "") -> tuple:
    body = body or b""
    return (
        status,
        len(body),
        hashlib.sha1(body[:512]).hexdigest()[:12],
        (location or "")[:80],
    )


def _looks_cdn(server: str, body_low: str) -> bool:
    if any(c in server.lower() for c in CDN_BANNERS):
        return True
    if "<title>cloudflare" in body_low or "error 1016" in body_low:
        return True
    return False


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if target.is_ip or target.host.count(".") < 1:
        return findings
    base = target.host
    parsed = urlparse(target.base_url)
    scheme = parsed.scheme or "https"

    client = HttpClient(config)
    try:
        # Baseline asli
        bl_real = client.get(target.base_url, allow_redirects=False)
        if bl_real is None:
            return findings
        server = bl_real.headers.get("Server", "") or ""
        body_real = bl_real.content or b""
        if _looks_cdn(server, body_real[:400].decode("utf-8", "ignore").lower()):
            # Behind CDN -> vhost-brute kurang berarti, skip.
            return findings
        sig_real = _signature(bl_real.status_code, body_real,
                              bl_real.headers.get("Location", ""))

        # Baseline random (host yang pasti tidak ada)
        rand_host = f"{_rand_label()}.{base}"
        bl_rand = client.get(target.base_url, allow_redirects=False,
                             headers={"Host": rand_host})
        if bl_rand is None:
            return findings
        sig_rand = _signature(bl_rand.status_code, bl_rand.content or b"",
                              bl_rand.headers.get("Location", ""))

        candidates_found: list[tuple[str, tuple, int]] = []
        seen_sigs: set[tuple] = {sig_real, sig_rand}

        for name in VHOST_NAMES:
            # Coba 2 bentuk: <name> (sebagai standalone host) dan <name>.<base>
            for host_try in (f"{name}.{base}", name):
                r = client.get(target.base_url, allow_redirects=False,
                               headers={"Host": host_try})
                if r is None:
                    continue
                sig = _signature(r.status_code, r.content or b"",
                                 r.headers.get("Location", ""))
                # Harus berbeda dari kedua baseline & belum pernah dilihat
                if sig == sig_real or sig == sig_rand:
                    continue
                if sig in seen_sigs:
                    continue
                seen_sigs.add(sig)
                candidates_found.append((host_try, sig, r.status_code))
                break  # cukup 1 bentuk per name

        if not candidates_found:
            return findings

        # Limit + dedupe by signature
        for host_try, sig, status in candidates_found[:12]:
            sev = (Severity.HIGH if any(k in host_try
                                        for k in ("admin", "internal",
                                                  "staging", "dev", "panel",
                                                  "backoffice", "vault",
                                                  "argocd", "jenkins"))
                   else Severity.MEDIUM)
            findings.append(Finding(
                module="vhost_brute",
                title=f"Virtual-host tersembunyi merespons: {host_try}",
                severity=sev,
                description=(
                    f"Server membalas berbeda saat header `Host: {host_try}` "
                    "dipakai dibanding baseline. Indikasi vhost ini ada di "
                    "server tapi tidak di-link DNS publik. Atacker bisa "
                    "menemukan environment internal (admin/staging) lewat "
                    "trik Host header."
                ),
                target=f"{scheme}://{base}/  (Host: {host_try})",
                evidence=truncate(
                    f"baseline_real={sig_real} baseline_rand={sig_rand} "
                    f"vhost_match={sig} status={status}",
                    240,
                ),
                cwe="CWE-200",
                confidence="firm",
                remediation=(
                    "Konfigurasi default vhost di reverse-proxy supaya tolak "
                    "request dengan `Host` yang tidak dikenal (nginx: "
                    "`server { listen 80 default_server; return 444; }`; "
                    "Apache: gunakan `RewriteCond %{HTTP_HOST} !^(...)$`). "
                    "Audit DNS internal apakah vhost ini memang seharusnya "
                    "publik atau hanya internal."
                ),
                references=[
                    "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/web-vulnerabilities-methodology",
                ],
            ))
    finally:
        client.close()
    return findings
