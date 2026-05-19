"""LDAP injection probe — strict-validation v0.10.4.

Sebelumnya: keyword ``ldap``/``invalid dn``/``search filter`` flag.
Banyak halaman generic punya kata "ldap" (mis. SSO settings, docs)
sehingga FP tinggi.

Sekarang flag HANYA bila signature error LDAP spesifik muncul setelah
payload TAPI tidak di response baseline (form login dengan creds string
biasa).
"""
from __future__ import annotations

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

LDAP_PAYLOADS = [
    "*)(uid=*))(|(uid=*",
    "*)(&(objectClass=*",
    "admin)(|(password=*))",
]
ERROR_HINT = (
    "ldap: invalid",
    "ldap_search",
    "javax.naming.directory.invalidsearchfilterexception",
    "openldap",
    "ad_search filter",
    "ldap_search_ext",
    "could not bind to ldap server",
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings
    form = next(
        (f for f in s.forms if any(
            (i.get("type") or "").lower() == "password" for i in f["inputs"]
        )),
        None,
    )
    if not form:
        return findings
    user_field = next(
        (i["name"] for i in form["inputs"]
         if (i.get("name") or "").lower() in ("username", "user", "uid")),
        None,
    )
    pass_field = next(
        (i["name"] for i in form["inputs"]
         if (i.get("type") or "").lower() == "password"),
        None,
    )
    if not (user_field and pass_field):
        return findings

    client = HttpClient(config)
    try:
        baseline = client.post(
            form["action"],
            data={user_field: "cyberloka_baseline", pass_field: "wrong"},
        )
        base_low = (baseline.text or "").lower() if baseline is not None else ""
        if any(e in base_low for e in ERROR_HINT):
            return findings  # baseline already noisy

        for payload in LDAP_PAYLOADS:
            r = client.post(
                form["action"],
                data={user_field: payload, pass_field: "x"},
            )
            if r is None:
                continue
            body = (r.text or "").lower()
            triggered = [e for e in ERROR_HINT if e in body]
            if not triggered:
                continue
            proof = ValidationProof(
                method="error-leak+baseline-clean",
                confirmed=True,
                steps=[
                    "Baseline POST dengan creds string biasa -> tidak ada signature LDAP.",
                    f"Probe POST dengan `{payload}` -> signature: {triggered[:3]}.",
                ],
                samples=[f"payload={payload}, signatures={triggered[:3]}"],
            )
            findings.append(Finding(
                module="ldap_injection", target=form["action"],
                title="LDAP injection error terkonfirmasi (baseline clean)",
                severity=Severity.HIGH,
                description=(
                    "Form login membongkar signature error LDAP setelah input "
                    "mengandung karakter filter LDAP, sementara baseline normal "
                    "tidak memunculkan signature tersebut."
                ),
                evidence=f"payload={payload}; signatures={triggered[:3]}",
                cwe="CWE-90",
                confidence="confirmed",
                urls=[form["action"]],
                remediation=(
                    "Escape karakter LDAP filter (`(`, `)`, `*`, `\\`, NUL) "
                    "sebelum masuk ke filter string. Pakai parametrik LDAP API."
                ),
                extra=build_extra(proof=proof),
            ))
            return findings
    finally:
        client.close()
    return findings
