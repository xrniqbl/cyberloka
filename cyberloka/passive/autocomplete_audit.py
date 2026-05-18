"""Audit autocomplete attribute on sensitive form fields."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

SENSITIVE_FIELDS = re.compile(
    r"(password|passwd|cc[-_]?number|card[-_]?number|ccv|cvv|pin)",
    re.I,
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url)
        if r is None:
            return findings
        body = r.text or ""
        # Find input tags with name like password/cc/cvv that don't have autocomplete=off
        for m in re.finditer(r"<input[^>]*>", body, re.I):
            tag = m.group(0)
            if not SENSITIVE_FIELDS.search(tag):
                continue
            if 'autocomplete="off"' not in tag.lower() and "autocomplete='off'" not in tag.lower():
                if 'autocomplete=' not in tag.lower() or 'autocomplete="on"' in tag.lower():
                    findings.append(Finding(
                        module="autocomplete_audit", target=target.base_url,
                        title="Form sensitif tanpa autocomplete=off",
                        severity=Severity.LOW,
                        description=("Input password/CC/CVV dengan autocomplete=on dapat disimpan "
                                     "browser pengunjung. Pada komputer publik / Wi-Fi cafe ini "
                                     "berisiko kebocoran."),
                        evidence=tag[:160],
                        cwe="CWE-525",
                        remediation=("Tambahkan `autocomplete=\"off\"` pada input password, CC, "
                                     "dan CVV. Untuk login user-friendly, pakai `autocomplete="
                                     "\"current-password\"` saja, jangan card number."),
                    ))
                    return findings
    finally:
        client.close()
    return findings
