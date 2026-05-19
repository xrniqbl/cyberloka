"""SSRF probe — strict-validation v0.10.4.

Sebelumnya: scanner flag setiap response 200 yang berisi ``<title>`` atau
kata ``localhost`` di body. Itu menghasilkan banyak false-positive karena
hampir semua halaman HTML punya ``<title>``.

Sekarang konfirmasi:
- Baseline benign: kirim URL eksternal aman (example.com) sebagai value
  parameter; simpan response.
- Kirim probe internal (metadata cloud / file:///etc/passwd / 127.0.0.1).
- Hanya flag kalau response memuat **signature spesifik** dari endpoint
  yang dituju (mis. ``ami-id``, ``computeMetadata/v1``, ``root:x:0:0``)
  DAN signature itu TIDAK muncul di baseline benign.
"""
from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    body_similarity,
    build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

URL_PARAM_HINTS = (
    "url", "uri", "redirect", "next", "image", "fetch", "dest", "callback",
    "src", "target", "feed", "host", "endpoint", "preview",
)

# (probe_url, marker_lowercase, severity_bonus)
PROBES = [
    ("http://169.254.169.254/latest/meta-data/", "ami-id", True),
    ("http://metadata.google.internal/computeMetadata/v1/", "metadata-flavor", True),
    ("file:///etc/passwd", "root:x:0:0", True),
    ("http://127.0.0.1:80/", None, False),  # banner-style fallback
]

# Indikator banner internal service — hanya dipakai untuk probe yang
# tidak punya marker spesifik (127.0.0.1).
_BANNER_HINTS = (
    "HTTP/1.0 ", "HTTP/1.1 ", "Server: nginx", "Server: Apache",
    "<title>Welcome to nginx", "<title>Apache HTTP Server",
)


def _candidates(base_url: str, urls: list[str]) -> list[str]:
    pool = set([base_url] + urls)
    matches: list[str] = []
    for u in pool:
        q = urlparse(u).query
        if not q:
            continue
        for k, _ in parse_qsl(q, keep_blank_values=True):
            if any(h in k.lower() for h in URL_PARAM_HINTS):
                matches.append(u)
                break
    return matches[:15]


def _benign_url() -> str:
    # IANA documentation domain — aman dipakai sebagai baseline diff.
    return f"https://example.com/?cyberloka_baseline={secrets.token_hex(3)}"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    state = get_state(config)
    urls = state.param_urls if state else []
    candidates = _candidates(target.base_url, urls)
    if not candidates:
        return []
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for url in candidates:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            for i, (k, _) in enumerate(params):
                if not any(h in k.lower() for h in URL_PARAM_HINTS):
                    continue

                # Baseline benign: eksternal yang aman.
                benign_url_value = _benign_url()
                new_b = list(params)
                new_b[i] = (k, benign_url_value)
                benign_full_url = urlunparse(parsed._replace(query=urlencode(new_b)))
                r_benign = client.get(benign_full_url)
                benign_body = (r_benign.text or "") if r_benign is not None else ""

                for probe_url, marker, is_critical in PROBES:
                    new = list(params)
                    new[i] = (k, probe_url)
                    mutated = urlunparse(parsed._replace(query=urlencode(new)))
                    headers = {"Metadata": "true", "Metadata-Flavor": "Google"}
                    r = client.get(mutated, headers=headers)
                    if r is None or r.status_code >= 500:
                        continue
                    body = r.text or ""
                    body_low = body.lower()

                    if marker:
                        # Marker harus ada di response probe TAPI tidak di baseline.
                        if marker not in body_low:
                            continue
                        if marker in benign_body.lower():
                            # Marker juga muncul di baseline -> false oracle.
                            continue
                        confirmed = True
                        evidence = (
                            f"probe={probe_url}; status={r.status_code}; "
                            f"marker `{marker}` muncul di response, tidak di baseline"
                        )
                    else:
                        # Probe tanpa marker spesifik (127.0.0.1):
                        # response harus berbeda jelas dari baseline DAN
                        # memuat banner internal service.
                        if body.strip() == benign_body.strip():
                            continue
                        sim = body_similarity(benign_body, body)
                        has_banner = any(b in body for b in _BANNER_HINTS)
                        if sim > 0.85 or not has_banner:
                            continue
                        confirmed = True
                        evidence = (
                            f"probe={probe_url}; status={r.status_code}; "
                            f"sim(benign,probe)={sim:.2f}; banner internal terdeteksi"
                        )

                    if not confirmed:
                        continue

                    sev = Severity.CRITICAL if is_critical else Severity.HIGH
                    proof = ValidationProof(
                        method="benign-baseline+probe-marker",
                        confirmed=True,
                        steps=[
                            f"Baseline: parameter `{k}` diisi URL eksternal aman "
                            f"({benign_url_value}).",
                            f"Probe: parameter `{k}` diisi `{probe_url}`.",
                            "Response probe memuat signature internal yang "
                            "TIDAK ada di baseline -> server fetch URL probe.",
                        ],
                        samples=[evidence],
                    )
                    findings.append(
                        Finding(
                            module="ssrf",
                            title=f"SSRF terkonfirmasi pada parameter `{k}`",
                            severity=sev,
                            description=(
                                "Server fetch URL yang dikontrol klien. Response "
                                "berbeda signifikan dari baseline (URL eksternal aman) "
                                "dan memuat signature spesifik endpoint internal / "
                                "metadata cloud yang dituju. Penyerang dapat "
                                "menyentuh service internal."
                            ),
                            target=mutated,
                            evidence=evidence,
                            cwe="CWE-918",
                            confidence="confirmed",
                            urls=[mutated],
                            remediation=(
                                "Whitelist domain target, blokir IP private "
                                "(RFC1918, 169.254.0.0/16), tolak skema selain "
                                "http(s), batasi redirect."
                            ),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                            ],
                            extra=build_extra(proof=proof),
                        )
                    )
                    return findings
    finally:
        client.close()
    return findings
