"""Subdomain takeover detection via CNAME fingerprint + body markers."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import load_data_lines

try:
    import dns.resolver  # type: ignore
except ImportError:  # pragma: no cover
    dns = None  # type: ignore

# (cname pattern, body fingerprint, vendor)
TAKEOVER_FINGERPRINTS: list[tuple[str, str, str]] = [
    ("amazonaws.com", "NoSuchBucket", "AWS S3"),
    ("herokuapp.com", "no such app", "Heroku"),
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("azurewebsites.net", "404 Web Site not found", "Azure App Service"),
    ("cloudapp.net", "404 Web Site not found", "Azure Cloud"),
    ("trafficmanager.net", "Page not found", "Azure Traffic Manager"),
    ("readme.io", "Project doesnt exist", "Readme.io"),
    ("readthedocs.io", "unknown to Read the Docs", "Read the Docs"),
    ("ghost.io", "The thing you were looking for is no longer here", "Ghost"),
    ("zendesk.com", "Help Center Closed", "Zendesk"),
    ("tumblr.com", "There's nothing here.", "Tumblr"),
    ("shopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("fastly.net", "Fastly error: unknown domain", "Fastly"),
    ("pantheonsite.io", "The gods are wise", "Pantheon"),
    ("wpengine.com", "The site you were looking for couldn", "WP Engine"),
    ("netlify.app", "Not Found - Request ID", "Netlify"),
    ("surge.sh", "project not found", "Surge"),
    ("bitbucket.io", "Repository not found", "Bitbucket"),
    ("helpscoutdocs.com", "No settings were found for this company", "Help Scout"),
    ("statuspage.io", "You are being redirected", "Statuspage"),
    ("unbouncepages.com", "The requested URL was not found", "Unbounce"),
]


def _cname(host: str) -> str | None:
    if dns is None:
        return None
    try:
        ans = dns.resolver.resolve(host, "CNAME", lifetime=4.0)
        for r in ans:
            return r.to_text().rstrip(".")
    except Exception:  # noqa: BLE001
        return None
    return None


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _check_host(client: HttpClient, host: str) -> tuple[str, str, str] | None:
    """Return (cname, vendor, evidence) if takeover risk detected."""
    cname = _cname(host)
    if not cname:
        return None
    cname_l = cname.lower()
    matched_vendor = None
    matched_marker = None
    for cn_pat, body_marker, vendor in TAKEOVER_FINGERPRINTS:
        if cn_pat in cname_l:
            matched_vendor = vendor
            matched_marker = body_marker
            break
    if not matched_vendor:
        return None
    # If CNAME exists but A record fails -> likely dangling
    a = _resolve(host)
    if a is None:
        return cname, matched_vendor, f"CNAME {cname} tidak punya A record (dangling)"
    # Else fetch and search marker
    for scheme in ("https", "http"):
        r = client.get(f"{scheme}://{host}/", allow_redirects=False)
        if r is None:
            continue
        body = (r.text or "")[:8192]
        if matched_marker.lower() in body.lower():
            return cname, matched_vendor, f"Marker '{matched_marker}' ditemukan via {scheme}"
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if target.is_ip or dns is None:
        return findings

    base = target.host
    if base.count(".") < 1:
        return findings

    words = load_data_lines("subdomains.txt") or []
    candidates = [f"{w}.{base}" for w in words[:200]]
    candidates.append(base)

    client = HttpClient(config)
    try:
        with ThreadPoolExecutor(max_workers=min(20, config.threads * 2)) as ex:
            futures = {ex.submit(_check_host, client, h): h for h in candidates}
            for fut in as_completed(futures):
                host = futures[fut]
                res = fut.result()
                if not res:
                    continue
                cname, vendor, ev = res
                findings.append(
                    Finding(
                        module="subdomain_takeover",
                        title=f"Potensi subdomain takeover ({vendor}): {host}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Subdomain `{host}` mengarah ke `{cname}` tetapi resource "
                            f"di {vendor} tidak ada / dangling. Attacker dapat mengklaim "
                            "resource dan menjalankan konten arbitrer di bawah nama domain Anda."
                        ),
                        target=host,
                        evidence=f"CNAME: {cname}\n{ev}",
                        cwe="CWE-350",
                        remediation=(
                            "Hapus CNAME yang tidak terpakai di DNS. Buat proses inventarisasi "
                            "DNS rutin (asset management) sehingga record yang tidak dipakai "
                            "segera dibersihkan."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Subdomain_Takeover",
                            "https://github.com/EdOverflow/can-i-take-over-xyz",
                        ],
                    )
                )
    finally:
        client.close()
    return findings
