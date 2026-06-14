"""LDAP filter injection on login forms — verification-first.

Versi lama: kata "ldap"/"search filter" di body → flag. Kini: error harus ABSEN saat
login benign, MUNCUL setelah payload filter, dan kontrol benign tetap bersih.
"""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

LDAP_PAYLOADS = [
    "*)(uid=*))(|(uid=*",
    "*)(&(objectClass=*",
    "admin)(|(password=*))",
]
ERROR_HINT = ("ldap", "invalid dn", "search filter", "ldap_search", "openldap", "ad_search")


def _has_error(text: str | None) -> bool:
    low = (text or "").lower()
    return any(e in low for e in ERROR_HINT)


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
        # Baseline: login benign biasa tidak boleh memunculkan error LDAP.
        base = client.post(form["action"], data={user_field: "cyberlokauser", pass_field: "cyberlokapw"})
        if base is None or _has_error(base.text):
            return findings
        for payload in LDAP_PAYLOADS:
            r = client.post(form["action"], data={user_field: payload, pass_field: "x"})
            if r is None or not _has_error(r.text):
                continue
            # Konfirmasi: login benign lain tetap bersih → error dipicu karakter filter.
            ctrl = client.post(form["action"], data={user_field: "cyberlokauser2", pass_field: "x"})
            if ctrl is not None and _has_error(ctrl.text):
                continue
            findings.append(Finding(
                module="ldap_injection", target=form["action"],
                title="LDAP injection TERVERIFIKASI (error dipicu karakter filter)",
                severity=Severity.HIGH,
                confidence="confirmed",
                description=("Error LDAP ABSEN saat login benign tapi MUNCUL setelah input "
                             "mengandung karakter filter `*)(` — backend menyusun filter LDAP "
                             "dari input tanpa escape."),
                evidence=f"payload={payload!r}; error absen di baseline+kontrol",
                cwe="CWE-90",
                remediation=("Escape karakter LDAP filter (`(`, `)`, `*`, `\\`, NUL) sebelum masuk "
                             "ke filter string. Pakai parametrik LDAP API."),
            ))
            return findings
    finally:
        client.close()
    return findings
