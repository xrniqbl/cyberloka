"""Static DOM-XSS hint via JS pattern matching (no execution)."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# (sink regex, label)
SINK_PATTERNS = [
    (re.compile(r"\.innerHTML\s*=\s*[^;]*location\.(?:hash|search|href)"), "innerHTML <- location"),
    (re.compile(r"document\.write\s*\(\s*[^)]*location\.(?:hash|search|href)"), "document.write <- location"),
    (re.compile(r"\beval\s*\(\s*[^)]*location\.(?:hash|search|href)"), "eval <- location"),
    (re.compile(r"\bnew\s+Function\s*\(\s*[^)]*location\."), "new Function <- location"),
    (re.compile(r"setTimeout\s*\(\s*[^,)]*location\."), "setTimeout <- location"),
    (re.compile(r"\.outerHTML\s*=\s*[^;]*location\."), "outerHTML <- location"),
    (re.compile(r"window\.postMessage\s*\([^,)]*\*"), "postMessage targetOrigin = '*'"),
]


def _candidate_scripts(client: HttpClient, target: Target) -> list[str]:
    r = client.get(target.base_url)
    if r is None:
        return []
    body = r.text or ""
    urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body):
        urls.add(urljoin(target.base_url, m.group(1)))
    return list(urls)[:8]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for url in _candidate_scripts(client, target):
            r = client.get(url)
            if r is None or r.status_code != 200:
                continue
            text = r.text or ""
            for pattern, label in SINK_PATTERNS:
                m = pattern.search(text)
                if m:
                    findings.append(Finding(
                        module="dom_xss",
                        title=f"Pola DOM-XSS terdeteksi di {url} ({label})",
                        severity=Severity.MEDIUM,
                        description=("Static analysis menemukan sink JS yang menerima "
                                     "data dari `location` tanpa sanitasi. Verifikasi "
                                     "manual apakah dapat dieksploitasi."),
                        target=url,
                        evidence=m.group(0)[:200],
                        cwe="CWE-79", confidence="tentative",
                        remediation=("Hindari menulis HTML dari `location.*`. Gunakan "
                                     "`textContent` / `setAttribute`, atau library yang "
                                     "menyanitasi (DOMPurify)."),
                    ))
                    break
    finally:
        client.close()
    return findings
