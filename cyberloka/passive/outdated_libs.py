"""Detect outdated front-end JS libraries by version regex."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# (regex on URL/body, library, last_safe_version_string, advisory note)
LIB_RULES = [
    (re.compile(r"jquery[-.](\d+\.\d+\.\d+)", re.I), "jQuery", (3, 7, 1),
     "Versi jQuery <3.5 punya beberapa CVE prototype-pollution/XSS."),
    (re.compile(r"angular[.\-](\d+\.\d+\.\d+)", re.I), "AngularJS", (1, 8, 3),
     "AngularJS 1.x sudah end-of-life sejak 2022."),
    (re.compile(r"bootstrap[.\-](\d+\.\d+\.\d+)", re.I), "Bootstrap", (5, 3, 0),
     "Bootstrap <4.3 punya XSS CVE-2019-8331."),
    (re.compile(r"lodash[.\-](\d+\.\d+\.\d+)", re.I), "lodash", (4, 17, 21),
     "lodash <4.17.21 rentan prototype pollution."),
    (re.compile(r"vue[.\-](\d+\.\d+\.\d+)", re.I), "Vue.js", (3, 4, 0),
     "Versi Vue lama dapat memiliki bug parser HTML."),
]


def _ver_tuple(s: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in s.split("."))
    except ValueError:
        return (0,)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None:
            return findings
        body = resp.text or ""
        seen: set[tuple] = set()
        for rgx, lib, safe, note in LIB_RULES:
            for m in rgx.finditer(body):
                ver = m.group(1)
                key = (lib, ver)
                if key in seen:
                    continue
                seen.add(key)
                outdated = _ver_tuple(ver) < safe
                if not outdated:
                    continue
                findings.append(
                    Finding(
                        module="outdated_libs",
                        title=f"Library outdated: {lib} {ver}",
                        severity=Severity.MEDIUM,
                        description=note,
                        target=target.base_url,
                        evidence=m.group(0),
                        cwe="CWE-1035",
                        remediation=(
                            f"Upgrade {lib} ke versi >= {'.'.join(str(x) for x in safe)} "
                            "atau rilis stabil terbaru. Pertimbangkan SCA otomatis (npm audit, snyk)."
                        ),
                        references=[
                            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
                        ],
                    )
                )
    finally:
        client.close()
    return findings
