"""Tabnabbing — link target=_blank tanpa rel=noopener.

Saat halaman A meng-link ke halaman B dengan ``target="_blank"`` tanpa
``rel="noopener noreferrer"``, halaman B mendapat ``window.opener`` referensi
ke halaman A. B bisa secara silent mengganti A jadi halaman phishing
(reverse tabnabbing).

Sejak Chrome 88 / Firefox 79 default link sudah implicit noopener, tapi:
- Banyak browser lawas / WebView aplikasi mobile tidak ikut perubahan ini.
- ``window.open()`` di JavaScript TIDAK auto-noopener.

Modul ini parse HTML homepage (+ beberapa link internal high-value), enumerate
``<a target="_blank">`` ke domain eksternal, lalu lapor MEDIUM bila tidak ada
``rel`` yang berisi ``noopener`` / ``noreferrer``.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# Match <a ...> tags to extract attributes
A_TAG_RE = re.compile(r"<a\s+[^>]*?>", re.I | re.S)
ATTR_RE = re.compile(r"""(\w[\w-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.S)


def _parse_attrs(tag: str) -> dict:
    out = {}
    for m in ATTR_RE.finditer(tag):
        key = m.group(1).lower()
        val = m.group(2) or m.group(3) or m.group(4) or ""
        out[key] = val
    return out


def _is_external(href: str, base_host: str) -> bool:
    try:
        host = urlparse(href).hostname
    except Exception:
        return False
    if not host:
        return False
    base_host = (base_host or "").lower()
    host = host.lower()
    return host != base_host and not host.endswith("." + base_host)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url)
        if r is None:
            return findings
        body = r.text or ""

        bad: list[tuple[str, str]] = []
        for m in A_TAG_RE.finditer(body):
            attrs = _parse_attrs(m.group(0))
            if attrs.get("target", "").lower() != "_blank":
                continue
            href = attrs.get("href", "")
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            full = urljoin(target.base_url, href)
            if not _is_external(full, target.host):
                continue
            rel = (attrs.get("rel") or "").lower()
            if "noopener" in rel or "noreferrer" in rel:
                continue
            bad.append((full, m.group(0)))

        # De-dup by destination
        seen_dest: set[str] = set()
        for dest, tag in bad:
            host = urlparse(dest).hostname or dest
            if host in seen_dest:
                continue
            seen_dest.add(host)
            findings.append(
                Finding(
                    module="tabnabbing",
                    title=f"Link target=_blank tanpa rel=noopener ke {host}",
                    severity=Severity.MEDIUM,
                    description=(
                        "Halaman membuka link eksternal di tab baru tanpa "
                        "`rel='noopener noreferrer'`. Halaman tujuan dapat memanfaatkan "
                        "`window.opener.location = 'https://phishing.example/login'` "
                        "untuk mengganti tab asli jadi halaman phishing yang menipu "
                        "pengunjung — reverse tabnabbing klasik."
                    ),
                    target=target.base_url,
                    evidence=f"link: {dest}\ntag: {truncate(tag, 200)}",
                    cwe="CWE-1022",
                    confidence="confirmed",
                    urls=[dest],
                    remediation=(
                        "Tambahkan `rel='noopener noreferrer'` pada SEMUA "
                        "`<a target=\"_blank\">`. Untuk JS yang pakai `window.open()`, "
                        "set property `opener = null` setelah open. Browser modern sudah "
                        "default-nya implicit noopener, tapi WebView / browser lawas "
                        "belum semua."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Reverse_Tabnabbing",
                        "https://cwe.mitre.org/data/definitions/1022.html",
                    ],
                )
            )
    finally:
        client.close()
    return findings
