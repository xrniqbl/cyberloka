"""Cek apakah server membocorkan stack trace / debug info / path internal di
response error (404, 500, dst).
"""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

_TRACE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)", re.I)),
    ("PHP error", re.compile(r"<b>(?:Warning|Notice|Fatal error|Parse error)</b>", re.I)),
    ("PHP error (text)", re.compile(r"PHP (?:Warning|Notice|Fatal error|Parse error)", re.I)),
    ("Java stack trace", re.compile(r"\sat\s+[\w.$]+\([\w.$]+\.java:\d+\)")),
    ("ASP.NET YSOD", re.compile(r"Server Error in '/' Application", re.I)),
    ("Node stack", re.compile(r"at\s+\w+\s+\(/[\w/.-]+\.js:\d+:\d+\)")),
    ("Ruby/Rails error", re.compile(r"ActionController::|ActiveRecord::", re.I)),
    ("Path internal Linux", re.compile(r"/(?:home|var/www|opt|srv)/[a-zA-Z0-9_./-]+\.(?:py|php|rb|js)")),
    ("Path internal Windows", re.compile(r"[A-Z]:\\(?:Users|inetpub|wwwroot)\\[\w\\.-]+")),
    ("Database connection error", re.compile(
        r"(?:could not connect to|sqlstate\[hy000\]|access denied for user|"
        r"connection refused|no such table|relation \"\w+\" does not exist)",
        re.I,
    )),
]


def _scan(label: str, body: str) -> list[Finding]:
    out: list[Finding] = []
    for name, rgx in _TRACE_PATTERNS:
        m = rgx.search(body or "")
        if not m:
            continue
        out.append(
            Finding(
                module="error_disclosure",
                title=f"Information disclosure di error response: {name}",
                severity=Severity.MEDIUM,
                description=(
                    "Server menampilkan stack trace / path internal / detail database "
                    "saat terjadi error. Attacker dapat memetakan struktur aplikasi & "
                    "menemukan vector serangan."
                ),
                target=label,
                evidence=truncate(m.group(0), 200),
                cwe="CWE-209",
                remediation=(
                    "Production: tampilkan halaman error generik. Log detail error di "
                    "server-side saja. Set DEBUG=False (Django/Flask), display_errors=Off "
                    "(PHP), production env (Rails/Node)."
                ),
                references=[
                    "https://owasp.org/www-community/Improper_Error_Handling",
                ],
            )
        )
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # Probe halaman 404
        probe_404 = target.origin + "/cyberloka-nonexistent-" + "x" * 8
        for url in (target.base_url, probe_404):
            resp = client.get(url, allow_redirects=False)
            if resp is None or not resp.text:
                continue
            findings.extend(_scan(url, resp.text))

        # Trigger error via parameter aneh kalau ada query string
        if "?" in target.base_url:
            err_url = target.base_url + "&cyberloka_test=' OR 1=1"
            resp = client.get(err_url)
            if resp is not None and resp.text:
                findings.extend(_scan(err_url, resp.text))
    finally:
        client.close()

    # Dedup by title+target (sering duplicate antar URL)
    seen: set[tuple[str, str]] = set()
    deduped: list[Finding] = []
    for f in findings:
        key = (f.title, f.target)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped
