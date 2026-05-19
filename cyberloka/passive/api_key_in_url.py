"""Detect API keys passed via URL query (leak via Referer/log)."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from cyberloka.core import Finding, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

KEY_PARAMS = re.compile(
    r"^(api[_-]?key|apikey|token|access[_-]?token|auth[_-]?token|"
    r"secret|password|passwd|pwd|key|sig|signature|sessionid|sid|jwt)$",
    re.I,
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings
    leaks: list[str] = []
    seen: set[tuple] = set()
    for u in s.urls + s.param_urls:
        parsed = urlparse(u)
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            if KEY_PARAMS.match(k) and v and len(v) >= 8:
                key = (parsed.path, k)
                if key in seen:
                    continue
                seen.add(key)
                leaks.append(f"{u} — `{k}` length {len(v)}")
    if leaks:
        findings.append(Finding(
            module="api_key_in_url", target=target.base_url,
            title=f"{len(leaks)} URL menerima credential lewat query string",
            severity=Severity.MEDIUM,
            description=("Parameter sensitif (api_key/token/password/jwt) dikirim lewat URL. "
                         "Berisiko bocor lewat: header Referer ke domain pihak ketiga, "
                         "log proxy/CDN/server, browser history, dan share URL."),
            evidence="\n".join(leaks[:10]),
            cwe="CWE-598",
            remediation=("Pindahkan credential ke header Authorization atau body POST. "
                         "Tambahkan `Referrer-Policy: no-referrer` pada page yang masih harus "
                         "memakai pattern lama."),
        ))
    return findings
