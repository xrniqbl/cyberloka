"""Calculate favicon hash for vendor/service identification."""
from __future__ import annotations

import codecs
import hashlib

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig


def _shodan_mmh3(content: bytes) -> str:
    """Best-effort: emulate Shodan's mmh3 hash via python's hashlib (not exact)."""
    try:
        import mmh3  # type: ignore
        b64 = codecs.encode(content, "base64")
        return str(mmh3.hash(b64))
    except ImportError:
        return ""


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.origin + "/favicon.ico")
        if r is None or r.status_code != 200:
            return findings
        content = r.content
        if not content:
            return findings
        md5 = hashlib.md5(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        mmh3_hash = _shodan_mmh3(content)
        findings.append(Finding(
            module="favicon_hash", target=target.origin + "/favicon.ico",
            title=f"Favicon hash terdeteksi (md5: {md5[:12]}…)",
            severity=Severity.INFO,
            description=("Hash favicon dapat dipakai attacker mencari instance lain dari vendor/"
                         "framework yang sama via Shodan / FOFA. Jika favicon = framework default, "
                         "ini membocorkan teknologi."),
            evidence=f"md5={md5}\nsha1={sha1}" + (f"\nmmh3={mmh3_hash}" if mmh3_hash else ""),
            cwe="CWE-200",
            remediation=("Pakai favicon kustom (bukan default framework). Untuk hardening: "
                         "kalau memang concern, set CSP frame-ancestors + serve favicon "
                         "dengan nama yang berbeda."),
        ))
    finally:
        client.close()
    return findings
