"""Form-aware fuzzer: tests SQLi/XSS reflections on discovered forms."""
from __future__ import annotations

import secrets

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state

XSS_TOKEN = secrets.token_hex(4)
XSS_PAYLOAD = f"<sCript>cyberloka{XSS_TOKEN}</sCript>"
SQLI_PAYLOAD = "1'\""

SQLI_SIGNS = (
    "sql syntax",
    "mysql",
    "sqlstate",
    "ora-0",
    "psql",
    "syntax error",
    "unclosed quotation",
)


def _submit(client: HttpClient, form: dict, payload: str):
    data = {
        i["name"]: payload if i["type"] not in ("submit", "button", "hidden") else (i["value"] or "x")
        for i in form["inputs"]
    }
    if not data:
        return None
    if form["method"] == "post":
        return client.post(form["action"], data=data)
    return client.get(form["action"], params=data)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    state = get_state(config)
    if not state or not state.forms:
        return []
    findings: list[Finding] = []
    client = HttpClient(config)
    seen: set[tuple] = set()
    try:
        for form in state.forms:
            key = (form["method"], form["action"], tuple(i["name"] for i in form["inputs"]))
            if key in seen:
                continue
            seen.add(key)

            r = _submit(client, form, XSS_PAYLOAD)
            if r is not None and XSS_PAYLOAD in (r.text or ""):
                ctype = r.headers.get("Content-Type", "").lower()
                if "html" in ctype:
                    findings.append(
                        Finding(
                            module="forms",
                            title=f"Reflected XSS via form `{form['action']}`",
                            severity=Severity.HIGH,
                            description=(
                                "Form mengembalikan input pengguna ke halaman tanpa "
                                "encoding yang aman."
                            ),
                            target=form["action"],
                            evidence=truncate(r.text or "", 240),
                            cwe="CWE-79",
                            remediation="Gunakan output encoding kontekstual + CSP ketat.",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                            ],
                        )
                    )

            r = _submit(client, form, SQLI_PAYLOAD)
            body = (r.text or "").lower() if r is not None else ""
            if any(s in body for s in SQLI_SIGNS):
                findings.append(
                    Finding(
                        module="forms",
                        title=f"Kemungkinan SQL Injection via form `{form['action']}`",
                        severity=Severity.CRITICAL,
                        description=(
                            "Form memunculkan error database setelah disuntik karakter "
                            "quote. Indikasi kuat SQLi."
                        ),
                        target=form["action"],
                        evidence=truncate(body, 240),
                        cwe="CWE-89",
                        remediation="Gunakan parameterized queries / prepared statements.",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                        ],
                    )
                )
    finally:
        client.close()
    return findings
