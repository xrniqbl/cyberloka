"""Detect Sentry/Mixpanel/Datadog/Segment write keys in JS bundles."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATTERNS = [
    (re.compile(r"https://[a-f0-9]{32}@[a-z0-9-]+\.ingest\.sentry\.io/\d+"),
     "Sentry DSN", Severity.LOW),
    (re.compile(r"['\"]([a-f0-9]{32})['\"][^,]*mixpanel", re.I),
     "Mixpanel project token", Severity.LOW),
    (re.compile(r"DD_CLIENT_TOKEN['\"]?\s*[:=]\s*['\"]pub[a-f0-9]{32}"),
     "Datadog client token", Severity.LOW),
    (re.compile(r"['\"]([a-zA-Z0-9]{32})['\"][^,]*segment", re.I),
     "Segment write key", Severity.MEDIUM),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key in JS", Severity.CRITICAL),
    (re.compile(r"firebaseConfig\s*=\s*\{[^}]+apiKey:\s*['\"][^'\"]+['\"]"),
     "Firebase config", Severity.LOW),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url)
        if r is None:
            return findings
        body = r.text or ""
        seen: set[str] = set()
        for rx, label, sev in PATTERNS:
            m = rx.search(body)
            if m and label not in seen:
                seen.add(label)
                findings.append(Finding(
                    module="sentry_dsn_leak", target=target.base_url,
                    title=f"Public client token terdeteksi: {label}",
                    severity=sev,
                    description=(f"Token analytics/error-tracking ({label}) ada di bundle JS publik. "
                                 "Ini wajar untuk client-token, tapi jangan sampai SECRET key bocor. "
                                 "Sentry DSN public dapat di-spam attacker untuk menggembungkan quota."),
                    evidence=m.group(0)[:80],
                    cwe="CWE-200",
                    remediation=("Pastikan ini token CLIENT (write-only), bukan API admin. "
                                 "Untuk Sentry: aktifkan rate-limit + Allowed Domains. "
                                 "Audit: jangan ada AWS key, JWT secret, atau database URI di JS."),
                ))
    finally:
        client.close()
    return findings
