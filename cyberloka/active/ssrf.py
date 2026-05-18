"""Server-Side Request Forgery (SSRF) probe (safe / non-destructive)."""
from __future__ import annotations

from urllib.parse import urlparse

from cyberloka.active._helpers import iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

SSRF_PARAM_HINTS = (
    "url", "uri", "next", "redirect", "callback", "webhook", "host",
    "domain", "site", "feed", "data", "fetch", "resource", "image",
    "img", "thumbnail", "preview", "link", "to", "target", "dest", "src",
)

# Safe target: link-local metadata-style URL but pointing to a non-routable
# loopback-only example. We do not target real cloud metadata IPs.
SAFE_PROBE = "http://127.0.0.1:1/"
EXTERNAL_PROBE = "http://example.com/"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if "?" not in target.base_url:
        return findings
    client = HttpClient(config)
    try:
        # Baseline response with normal value
        baseline = client.get(target.base_url)
        baseline_status = baseline.status_code if baseline else 0
        baseline_len = len(baseline.text) if (baseline and baseline.text) else 0

        for param, mutated in iter_param_urls(target.base_url, EXTERNAL_PROBE):
            if not any(h in param.lower() for h in SSRF_PARAM_HINTS):
                continue

            r = client.get(mutated, allow_redirects=False)
            if r is None:
                continue
            body = r.text or ""
            # Strong indicator: server fetched example.com and returned content
            external_marker = "Example Domain" in body or "iana.org" in body.lower()

            # Probe loopback to see different behavior (often error / 500)
            r2 = client.get(
                mutated.replace(EXTERNAL_PROBE, SAFE_PROBE), allow_redirects=False
            )
            loopback_diff = False
            if r2 is not None:
                if r2.status_code != baseline_status and r2.status_code >= 500:
                    loopback_diff = True
                if r2.text and any(s in r2.text.lower() for s in (
                    "connection refused", "no route to host", "timed out", "econnrefused"
                )):
                    loopback_diff = True

            if external_marker:
                findings.append(
                    Finding(
                        module="ssrf",
                        title=f"Indikasi SSRF di parameter `{param}` (server fetched URL eksternal)",
                        severity=Severity.HIGH,
                        description=(
                            "Server tampaknya mengambil URL dari parameter dan mengembalikan "
                            "kontennya ke client. Attacker bisa memaksa server memuat target "
                            "internal (cloud metadata, internal API, file://)."
                        ),
                        target=mutated,
                        evidence=f"baseline_len={baseline_len}, response_len={len(body)}",
                        cwe="CWE-918",
                        remediation=(
                            "Validasi & whitelist domain/IP target di server-side. Tolak "
                            "scheme `file://`, `gopher://`, `dict://`, dan IP private "
                            "(RFC1918, link-local 169.254.0.0/16, loopback). Gunakan "
                            "egress proxy yang membatasi outbound."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                        ],
                    )
                )
            elif loopback_diff:
                findings.append(
                    Finding(
                        module="ssrf",
                        title=f"Kemungkinan SSRF di parameter `{param}` (perbedaan respons saat loopback)",
                        severity=Severity.MEDIUM,
                        description=(
                            "Respons berbeda saat parameter berisi URL loopback. "
                            "Endpoint mungkin mengirim request HTTP server-side "
                            "berdasarkan input. Verifikasi manual dianjurkan."
                        ),
                        target=mutated,
                        evidence=f"loopback status={r2.status_code if r2 else 'n/a'}",
                        cwe="CWE-918",
                        confidence="tentative",
                        remediation=(
                            "Whitelist destinasi outbound, blokir IP private dan scheme "
                            "non-HTTP(S). Pisahkan worker yang melakukan fetch dari "
                            "jaringan internal."
                        ),
                    )
                )
    finally:
        client.close()
    return findings
