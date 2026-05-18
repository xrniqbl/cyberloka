"""Mixed content (HTTPS page loads HTTP resources)."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

ATTRS = {
    "script": "src",
    "link": "href",
    "img": "src",
    "iframe": "src",
    "video": "src",
    "audio": "src",
    "source": "src",
    "form": "action",
}


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    if target.scheme != "https":
        return findings
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None or not resp.text:
            return findings
        soup = BeautifulSoup(resp.text, "html.parser")
        offending: list[tuple[str, str]] = []
        for tag, attr in ATTRS.items():
            for el in soup.find_all(tag):
                val = el.get(attr)
                if not val:
                    continue
                full = urljoin(target.base_url, val)
                p = urlparse(full)
                if p.scheme == "http":
                    offending.append((tag, full))

        # also CSS url(http://..)
        for style in soup.find_all("style"):
            for m in re.finditer(r"url\(\s*['\"]?(http://[^'\")\s]+)", style.text or ""):
                offending.append(("style/url", m.group(1)))

        if offending:
            findings.append(
                Finding(
                    module="mixed_content",
                    title=f"Mixed content: {len(offending)} resource HTTP di halaman HTTPS",
                    severity=Severity.MEDIUM,
                    description=(
                        "Browser modern memblokir active mixed content (script/iframe). "
                        "Passive mixed content (gambar) tetap melemahkan integritas dan "
                        "memunculkan warning padlock."
                    ),
                    target=target.base_url,
                    evidence="\n".join(f"<{tag}> -> {url}" for tag, url in offending[:20]),
                    remediation=(
                        "Ubah semua URL aset menjadi HTTPS atau protocol-relative (`//`). "
                        "Aktifkan `Content-Security-Policy: upgrade-insecure-requests` "
                        "sebagai mitigasi sementara."
                    ),
                    references=[
                        "https://developer.mozilla.org/docs/Web/Security/Mixed_content",
                    ],
                )
            )
    finally:
        client.close()
    return findings
