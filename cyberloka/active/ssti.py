"""Server-Side Template Injection (SSTI) detection.

Strategi non-destruktif:
- Kirim ekspresi aritmatika sederhana yang khas tiap engine.
  Bila hasil evaluasi muncul di response body, mesin template terbukti
  mengeksekusi input user.
- Engine yang dideteksi:
  - Jinja2 / Django / Twig: {{7*7}}
  - Smarty: {7*7}
  - Freemarker: ${7*7}
  - Velocity / Pebble: #{7*7}
  - ERB (Ruby): <%= 7*7 %>
- Tidak menyuntikkan payload eksekusi (mis. config / __import__).
"""
from __future__ import annotations

from cyberloka.active._helpers import collect_target_urls, iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# Pasangan: (payload, expected_marker, engine_label)
PROBES = [
    ("cyberloka{{7*7}}cyberloka", "cyberloka49cyberloka", "Jinja2/Django/Twig"),
    ("cyberloka{7*7}cyberloka", "cyberloka49cyberloka", "Smarty/Handlebars-like"),
    ("cyberloka${7*7}cyberloka", "cyberloka49cyberloka", "Freemarker/Thymeleaf"),
    ("cyberloka#{7*7}cyberloka", "cyberloka49cyberloka", "Velocity/Pebble/Ruby string"),
    ("cyberloka<%= 7*7 %>cyberloka", "cyberloka49cyberloka", "ERB (Ruby)"),
    ("cyberloka{{ '7'*7 }}cyberloka", "cyberloka7777777cyberloka", "Jinja2 string-mul"),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    seen_param: set[str] = set()
    client = HttpClient(config)
    try:
        for url in collect_target_urls(target, default_param="q"):
            for payload, marker, engine in PROBES:
                for param, mutated in iter_param_urls(url, payload):
                    key = f"{url.split('?')[0]}|{param}|{engine}"
                    if key in seen_param:
                        continue
                    seen_param.add(key)
                    resp = client.get(mutated)
                    if resp is None:
                        continue
                    body = resp.text or ""
                    if marker in body:
                        idx = body.find(marker)
                        snippet = truncate(body[max(0, idx - 80) : idx + len(marker) + 80], 240)
                        findings.append(
                            Finding(
                                module="ssti",
                                title=f"Server-Side Template Injection ({engine}) pada `{param}`",
                                severity=Severity.CRITICAL,
                                description=(
                                    "Server mengevaluasi ekspresi template dari input user. "
                                    "SSTI sering eskalasi menjadi RCE (akses ke object internal "
                                    "framework, eksekusi method arbitrary)."
                                ),
                                target=mutated,
                                evidence=f"payload={payload}\nmarker={marker}\n{snippet}",
                                cwe="CWE-1336",
                                remediation=(
                                    "Jangan render input user sebagai template. Pisahkan data "
                                    "dari template; gunakan placeholder/parameter (mis. "
                                    "`render_template('x.html', name=user_input)` di Flask, "
                                    "BUKAN `render_template_string(user_input)`). Audit semua "
                                    "fungsi render_string-style."
                                ),
                                references=[
                                    "https://portswigger.net/web-security/server-side-template-injection",
                                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
                                ],
                            )
                        )
                        return findings
    finally:
        client.close()
    return findings
