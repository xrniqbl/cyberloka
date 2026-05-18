"""Insecure deserialization marker probe."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

# Markers in cookies / params / response
PATTERNS = [
    (re.compile(r"rO0AB[A-Za-z0-9+/=]{10,}"), "Java serialized object (rO0AB...)", Severity.CRITICAL),
    (re.compile(r"O:\d+:\"[A-Za-z_\\\\]+\":\d+:\\?\{"), "PHP serialized object", Severity.CRITICAL),
    (re.compile(r"a:\d+:\\?\{[is]:"), "PHP serialized array", Severity.HIGH),
    (re.compile(r"!!python/object"), "Python YAML pickle", Severity.CRITICAL),
    (re.compile(r"AAEAAAD/////AQAAAAAAAAAM"), ".NET BinaryFormatter", Severity.CRITICAL),
    (re.compile(r"__VIEWSTATE=[^&]{40,}"), "ASP.NET ViewState", Severity.HIGH),
    (re.compile(r"\beyJ\w{4,}=*"), "Possible base64 (verify)", Severity.LOW),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        seen: set[str] = set()
        urls = [target.base_url]
        s = get_state(config)
        if s:
            urls += s.urls[:5]
        for url in urls:
            r = client.get(url)
            if r is None:
                continue
            haystack = (r.text or "")[:50000]
            for c in r.cookies:
                haystack += f"\n{c.name}={c.value}"
            for rgx, label, sev in PATTERNS:
                if label.startswith("Possible base64"):
                    continue  # too noisy alone
                m = rgx.search(haystack)
                if m and label not in seen:
                    seen.add(label)
                    findings.append(Finding(
                        module="deserialization", target=url,
                        title=f"Format serialisasi terdeteksi di response: {label}",
                        severity=sev,
                        description=("Server tampak menerima/mengirim object terserialisasi. "
                                     "Insecure deserialization sering jadi vektor RCE."),
                        evidence=m.group(0)[:120],
                        cwe="CWE-502",
                        remediation=("Jangan deserialize input dari user. Pakai JSON saja. "
                                     "Untuk Java: Look-Ahead pattern. PHP: hindari unserialize() "
                                     "pada data eksternal. Python: tidak pernah pickle.loads(input)."),
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"],
                    ))
    finally:
        client.close()
    return findings
