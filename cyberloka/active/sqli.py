"""Detect (likely) SQL injection — error-based + boolean-based."""
from __future__ import annotations

import re

from cyberloka.active._helpers import append_param, iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

ERROR_SIGNATURES = [
    r"sql syntax.*mysql",
    r"warning.*mysql",
    r"valid mysql result",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlstate\[",
    r"odbc.*sql server",
    r"microsoft sql native client",
    r"pg::syntaxerror",
    r"postgresql.*error",
    r"sqlite\.",
    r"sqlite3::sqlexception",
    r"oracle.*ora-\d{4,}",
    r"you have an error in your sql syntax",
]
ERROR_RE = re.compile("|".join(ERROR_SIGNATURES), re.I)

QUOTE_PAYLOAD = "'\""
TRUE_PAYLOAD = " AND 1=1-- -"
FALSE_PAYLOAD = " AND 1=2-- -"


def _scan_url(client: HttpClient, url: str) -> list[tuple[str, str, str]]:
    """Return list of (param, signature, evidence)."""
    hits: list[tuple[str, str, str]] = []
    if "?" not in url:
        url = append_param(url, "id", "1")

    # Error-based
    for param, mutated in iter_param_urls(url, "1" + QUOTE_PAYLOAD):
        resp = client.get(mutated)
        if resp is None:
            continue
        m = ERROR_RE.search(resp.text or "")
        if m:
            hits.append((param, "error-based", truncate(m.group(0), 120)))

    # Boolean-based
    for param, mutated_true in iter_param_urls(url, "1" + TRUE_PAYLOAD):
        # craft matching false url
        false_url = mutated_true.replace(
            "1+AND+1%3D1--+-", "1+AND+1%3D2--+-"
        ).replace(TRUE_PAYLOAD, FALSE_PAYLOAD)
        if false_url == mutated_true:
            continue
        r1 = client.get(mutated_true)
        r2 = client.get(false_url)
        if r1 is None or r2 is None:
            continue
        if r1.status_code == r2.status_code and abs(len(r1.text) - len(r2.text)) > 200:
            hits.append(
                (
                    param,
                    "boolean-based",
                    f"len_true={len(r1.text)} vs len_false={len(r2.text)}",
                )
            )
    return hits


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        url = target.base_url
        hits = _scan_url(client, url)
        for param, sig, ev in hits:
            findings.append(
                Finding(
                    module="sqli",
                    title=f"Kemungkinan SQL Injection ({sig}) pada parameter `{param}`",
                    severity=Severity.CRITICAL,
                    description=(
                        "Respons aplikasi berubah / memuat error SQL setelah disuntik payload. "
                        "SQL Injection memungkinkan attacker membaca/menulis seluruh database."
                    ),
                    target=url,
                    evidence=ev,
                    cwe="CWE-89",
                    confidence="firm" if sig == "error-based" else "tentative",
                    remediation=(
                        "Gunakan parameterized query / prepared statements. JANGAN concatenate "
                        "input ke query. Untuk ORM, hindari raw SQL dengan input user. Tambahkan "
                        "validasi tipe + WAF sebagai lapis pertahanan tambahan."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    ],
                )
            )
    finally:
        client.close()
    return findings
