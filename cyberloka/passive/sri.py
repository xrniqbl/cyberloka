"""Subresource Integrity (SRI) check untuk script & CSS dari CDN pihak ketiga.

Halaman yang load script CDN tanpa atribut `integrity=` rentan supply-chain
attack: bila CDN ter-kompromi, attacker dapat menyuntikkan script jahat ke
seluruh user.
"""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts: list[dict] = []
        self.styles: list[dict] = []

    def handle_starttag(self, tag: str, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.scripts.append(a)
        elif tag == "link" and a.get("rel", "").lower() == "stylesheet" and a.get("href"):
            self.styles.append(a)


def _is_third_party(url: str, target_host: str) -> bool:
    try:
        h = urlparse(url).hostname or ""
    except ValueError:
        return False
    if not h:
        return False
    if h == target_host:
        return False
    # Sub-domain dari target sendiri dianggap own
    if h.endswith("." + target_host):
        return False
    return True


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None or "html" not in resp.headers.get("Content-Type", "").lower():
            return findings
        body = resp.text or ""
        parser = _Parser()
        try:
            parser.feed(body)
        except Exception:  # noqa: BLE001
            pass

        missing_sri: list[str] = []
        for s in parser.scripts:
            url = s.get("src") or ""
            if _is_third_party(url, target.host) and not s.get("integrity"):
                missing_sri.append(f"<script src='{url}'>")
        for c in parser.styles:
            url = c.get("href") or ""
            if _is_third_party(url, target.host) and not c.get("integrity"):
                missing_sri.append(f"<link rel=stylesheet href='{url}'>")

        if missing_sri:
            findings.append(
                Finding(
                    module="sri",
                    title=f"{len(missing_sri)} resource pihak ketiga tanpa SRI (Subresource Integrity)",
                    severity=Severity.MEDIUM,
                    description=(
                        "Script/CSS dari CDN dimuat tanpa atribut `integrity`. Bila CDN "
                        "ter-kompromi atau di-MITM, attacker dapat menyuntikkan kode "
                        "jahat ke browser semua pengunjung Anda."
                    ),
                    target=target.base_url,
                    evidence="\n".join(missing_sri[:10]),
                    cwe="CWE-353",
                    remediation=(
                        "Tambahkan atribut integrity berisi hash SHA-384 dari resource. "
                        "Generate dengan: openssl dgst -sha384 -binary file.js | openssl base64 -A"
                    ),
                    references=[
                        "https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity",
                    ],
                )
            )
    finally:
        client.close()
    return findings
