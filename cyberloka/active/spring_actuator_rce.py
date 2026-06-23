"""Spring Boot Actuator exposure (env, heapdump, jolokia, mappings).

Auto-validation: probe /actuator/* dan validasi response JSON khas Spring
Boot (key `propertySources`, `mappings`, `_links`, `application`, dll).
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# (path, validator_substring, severity_override)
ACTUATOR_PATHS: list[tuple[str, list[str], Severity]] = [
    ("/actuator",          ['"_links"', '"actuator"', '"health"'], Severity.MEDIUM),
    ("/actuator/env",      ['"propertySources"', '"systemEnvironment"'], Severity.CRITICAL),
    ("/env",               ['"propertySources"', '"systemEnvironment"'], Severity.CRITICAL),
    ("/actuator/heapdump", ["JAVA PROFILE", "HPROF", "\x1f\x8b"], Severity.CRITICAL),
    ("/heapdump",          ["JAVA PROFILE", "HPROF", "\x1f\x8b"], Severity.CRITICAL),
    ("/actuator/jolokia",  ['"agent"', '"protocol"', "jolokia"], Severity.CRITICAL),
    ("/jolokia",           ['"agent"', '"protocol"', "jolokia"], Severity.CRITICAL),
    ("/actuator/mappings", ['"contexts"', '"dispatcherServlets"'], Severity.HIGH),
    ("/actuator/beans",    ['"contexts"', '"beans"'], Severity.HIGH),
    ("/actuator/threaddump", ['"threads"', '"threadName"'], Severity.HIGH),
    ("/actuator/configprops", ['"contexts"', '"contextId"'], Severity.HIGH),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    seen = set()
    try:
        for path, signatures, sev in ACTUATOR_PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            body_head = (r.text or "")[:4096]
            if not any(sig in body_head for sig in signatures):
                continue
            key = path.split("/")[-1]
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                module="spring_actuator_rce",
                title=f"Spring Boot Actuator ter-expose: {path}",
                severity=sev,
                description=(
                    "Endpoint actuator Spring Boot dapat diakses tanpa autentikasi. "
                    f"Path `{path}` mengandalikan ekstraksi kredensial / heapdump / "
                    "Jolokia chain ke RCE."
                ),
                target=url,
                urls=[url],
                evidence=f"GET {url} -> 200; signature match.",
                cwe="CWE-200",
                confidence="confirmed",
                remediation=(
                    "Aktifkan `spring.boot.admin.client.enabled=false` untuk "
                    "actuator publik, dan amankan dengan basic-auth: "
                    "`management.endpoints.web.exposure.include=health,info`. "
                    "Bind actuator ke localhost: "
                    "`management.server.port=-1` atau via reverse-proxy filter."
                ),
                references=[
                    "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
                    "https://www.veracode.com/blog/research/exploiting-spring-boot-actuators",
                ],
            ))
    finally:
        client.close()
    return findings
