"""Static + dynamic prototype-pollution heuristic."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

VULN_JS_PATTERNS = [
    re.compile(r"Object\.assign\s*\(\s*\w+\s*,\s*JSON\.parse"),
    re.compile(r"_\.merge\s*\("),
    re.compile(r"\$\.extend\s*\(\s*true"),
    re.compile(r"deepMerge\s*\("),
    re.compile(r"setIn\s*\("),
]
PAYLOADS = (
    "__proto__[polluted]=cyberloka",
    "constructor[prototype][polluted]=cyberloka",
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url)
        if r is not None:
            body = r.text or ""
            for pat in VULN_JS_PATTERNS:
                m = pat.search(body)
                if m:
                    findings.append(Finding(
                        module="proto_pollution",
                        title="Pola merge yang rentan prototype pollution di JS bundle",
                        severity=Severity.LOW,
                        description=("Pola fungsi merge mendalam yang sering jadi sumber "
                                     "prototype pollution ditemukan di kode klien. "
                                     "Verifikasi tidak menerima input user mentah."),
                        target=target.base_url,
                        evidence=m.group(0),
                        cwe="CWE-1321", confidence="tentative",
                        remediation=("Pakai `Object.create(null)`, freeze prototype, atau "
                                     "library yang aman seperti `lodash@>=4.17.21`. "
                                     "Sanitasi key sebelum merge: tolak `__proto__`, "
                                     "`constructor`, `prototype`."),
                    ))
                    break

        state = get_state(config)
        urls = state.param_urls if state else []
        for url in urls[:5]:
            parsed = urlparse(url)
            for payload in PAYLOADS:
                k, v = payload.split("=", 1)
                params = list(parse_qsl(parsed.query, keep_blank_values=True)) + [(k, v)]
                mutated = urlunparse(parsed._replace(query=urlencode(params)))
                r2 = client.get(mutated)
                if r2 is None:
                    continue
                body = (r2.text or "").lower()
                if "polluted" in body and "cyberloka" in body:
                    findings.append(Finding(
                        module="proto_pollution",
                        title=f"Endpoint memantulkan key prototype-pollution: {payload}",
                        severity=Severity.HIGH,
                        description=("Server-side menerima dan memantulkan parameter "
                                     "`__proto__` / `constructor[prototype]`. Sangat mungkin "
                                     "rentan prototype pollution (DoS atau RCE di Node.js)."),
                        target=mutated,
                        evidence=payload,
                        cwe="CWE-1321",
                        remediation=("Tolak key berbahaya di parser body/query. Update "
                                     "framework body-parser ke versi yang sudah patched "
                                     "(qs >=6.10, lodash >=4.17.21)."),
                        references=[
                            "https://snyk.io/learn/prototype-pollution-attacks/"
                        ],
                    ))
                    return findings
    finally:
        client.close()
    return findings
