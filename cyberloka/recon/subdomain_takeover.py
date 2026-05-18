"""Subdomain takeover heuristic: dangling CNAME → known fingerprints."""
from __future__ import annotations

import socket

import dns.resolver

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import load_data_lines

# (provider, signature substring in body, severity)
FINGERPRINTS = [
    ("GitHub Pages", "There isn't a GitHub Pages site here.", Severity.HIGH),
    ("Heroku", "no such app", Severity.HIGH),
    ("AWS S3", "NoSuchBucket", Severity.HIGH),
    ("Fastly", "Fastly error: unknown domain", Severity.HIGH),
    ("Shopify", "Sorry, this shop is currently unavailable.", Severity.HIGH),
    ("Tumblr", "Whatever you were looking for doesn't currently exist", Severity.MEDIUM),
    ("Unbounce", "The requested URL was not found on this server.", Severity.MEDIUM),
    ("Pantheon", "The gods are wise", Severity.MEDIUM),
    ("Surge.sh", "project not found", Severity.MEDIUM),
    ("Netlify", "Not Found - Request ID:", Severity.LOW),
]


def _candidates(target: Target) -> list[str]:
    subs = load_data_lines("subdomains.txt")[:60]
    return [f"{s}.{target.host}" for s in subs]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    if target.is_ip:
        return []
    findings: list[Finding] = []
    client = HttpClient(config)
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    try:
        for sub in _candidates(target):
            try:
                cnames = resolver.resolve(sub, "CNAME")
                cname = str(cnames[0].target).rstrip(".")
            except Exception:  # noqa: BLE001
                continue
            try:
                socket.gethostbyname(cname)
                resolves = True
            except OSError:
                resolves = False
            for proto in ("http", "https"):
                r = client.get(f"{proto}://{sub}/", allow_redirects=False)
                if r is None:
                    continue
                body = r.text or ""
                for provider, sig, sev in FINGERPRINTS:
                    if sig in body:
                        findings.append(
                            Finding(
                                module="subdomain_takeover",
                                title=f"Potensi subdomain takeover ({provider}) di {sub}",
                                severity=sev,
                                description=(
                                    f"Subdomain {sub} memiliki CNAME ke {cname} yang "
                                    f"sepertinya menunjuk ke layanan {provider} yang "
                                    "tidak terklaim."
                                ),
                                target=f"{proto}://{sub}/",
                                evidence=f"CNAME={cname}; resolves={resolves}; signature='{sig}'",
                                cwe="CWE-538",
                                remediation=(
                                    "Hapus CNAME yang dangling, atau klaim ulang resource "
                                    "di provider tujuan."
                                ),
                            )
                        )
                        break
    finally:
        client.close()
    return findings
