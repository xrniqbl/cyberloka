"""Information disclosure: HTML comments, debug pages, stack traces."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
SUSPICIOUS_COMMENT = re.compile(
    r"\b(todo|fixme|password|passwd|secret|api[_-]?key|token|debug|temp|disabled|hack|kludge|bug)\b",
    re.IGNORECASE,
)
STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)", re.I),
    re.compile(r"java\.lang\.[A-Za-z]+Exception", re.I),
    re.compile(r"at [A-Za-z0-9_.]+\([A-Za-z0-9_.:]+\)"),
    re.compile(r"PHP (Fatal|Warning|Notice)", re.I),
    re.compile(r"Microsoft .*Database.* Driver error", re.I),
    re.compile(r"ORA-\d{4,5}"),  # Oracle
    re.compile(r"Whitelabel Error Page"),  # Spring
    re.compile(r"Werkzeug Debugger"),
    re.compile(r"DEBUG = True", re.I),
    re.compile(r"You have an error in your SQL syntax", re.I),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None or not resp.text:
            return findings
        body = resp.text

        # HTML comments
        sus_comments = []
        for m in COMMENT_RE.finditer(body):
            content = m.group(1).strip()
            if not content or len(content) > 1000:
                continue
            if SUSPICIOUS_COMMENT.search(content):
                sus_comments.append(content)
        if sus_comments:
            findings.append(
                Finding(
                    module="info_disclosure",
                    title=f"HTML comment mencurigakan ({len(sus_comments)})",
                    severity=Severity.LOW,
                    description=(
                        "HTML comment dengan kata kunci sensitif terdeteksi. "
                        "Comments dapat membocorkan logic, kredensial, atau TODO untuk attacker."
                    ),
                    target=target.base_url,
                    evidence="\n---\n".join(truncate(c, 300) for c in sus_comments[:10]),
                    remediation=(
                        "Strip HTML comment di build pipeline (mis. plugin minifier). "
                        "Hapus referensi credential / TODO sensitif sebelum deploy."
                    ),
                )
            )

        # Stack trace / debug page
        for pat in STACK_TRACE_PATTERNS:
            m = pat.search(body)
            if m:
                findings.append(
                    Finding(
                        module="info_disclosure",
                        title="Stack trace / halaman debug ter-ekspos",
                        severity=Severity.HIGH,
                        description=(
                            "Halaman menampilkan stack trace atau halaman debug framework. "
                            "Ini membocorkan path file, versi library, dan dapat membantu RCE."
                        ),
                        target=target.base_url,
                        evidence=truncate(m.group(0), 300),
                        cwe="CWE-209",
                        remediation=(
                            "Nonaktifkan debug/development mode di production. Tampilkan "
                            "halaman error generik. Catat detail error ke log internal saja."
                        ),
                        references=[
                            "https://owasp.org/www-community/Improper_Error_Handling",
                        ],
                    )
                )
                break
    finally:
        client.close()
    return findings
