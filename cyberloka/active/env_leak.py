"""Environment & config leak detection — strict-validation v0.10.1.

Three sub-paths:
  1. Static pattern scan: response bodies for env-var-shaped secrets.
     Validation: dedupe per type+value, lalu cek pattern bukan dummy
     (mis. AKIA + EXAMPLE / TEST diabaikan).
  2. Error-induced stack-trace leak.
  3. Debug endpoint probe — diff vs negative control endpoint.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state
from cyberloka.reporting.awam import get_awam

SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID", Severity.CRITICAL),
    (re.compile(r"aws_secret_access_key\s*=\s*[\"']?([A-Za-z0-9/+=]{40})", re.I),
     "AWS secret access key", Severity.CRITICAL),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "Private key", Severity.CRITICAL),
    (re.compile(r"sk_live_[A-Za-z0-9]{20,}"), "Stripe live secret", Severity.CRITICAL),
    (re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
     "SendGrid API key", Severity.HIGH),
    (re.compile(r"xoxb-[A-Za-z0-9-]{10,}"), "Slack bot token", Severity.HIGH),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "GitHub personal access token", Severity.CRITICAL),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "GitHub fine-grained token", Severity.CRITICAL),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "Google API key", Severity.HIGH),
    (re.compile(r"DATABASE_URL\s*=\s*[\"']?([^\s\"']+)", re.I), "DATABASE_URL env", Severity.HIGH),
    (re.compile(r"MONGO(?:DB)?_URI\s*=\s*[\"']?(mongodb[^\s\"']+)", re.I),
     "MongoDB URI", Severity.HIGH),
    (re.compile(r"REDIS_URL\s*=\s*[\"']?(redis[^\s\"']+)", re.I), "Redis URL", Severity.HIGH),
    (re.compile(r"JWT_SECRET\s*=\s*[\"']?([A-Za-z0-9_-]{8,})", re.I),
     "JWT secret", Severity.HIGH),
    (re.compile(r"(?:DB|MYSQL|POSTGRES)_PASSWORD\s*=\s*[\"']?(\S+)", re.I),
     "Database password env", Severity.HIGH),
    (re.compile(r"NODE_ENV\s*=\s*[\"']?(development|debug)", re.I),
     "NODE_ENV non-production", Severity.MEDIUM),
]

STACKTRACE_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\):"), "Python traceback"),
    (re.compile(r"at\s+(?:com|org|java|sun|net)\.[\w.]+\(\w+\.java:\d+\)"), "Java stack frame"),
    (re.compile(r"at\s+\w+\.<anonymous>\s*\([^)]*\.js:\d+:\d+\)"), "Node.js stack frame"),
    (re.compile(r"in\s+(/(?:var|home|opt|usr|app)/[^\s)]+):\d+"), "PHP file path"),
    (re.compile(r"ORA-\d{5}"), "Oracle DB error"),
    (re.compile(r"PG::\w+Error"), "PostgreSQL error"),
    (re.compile(r"MySQL\s+server\s+version"), "MySQL error"),
]

DEBUG_PATHS = [
    "/__debug__/", "/__debug__",
    "/debug", "/debug/", "/?debug=1", "/?debug=true", "/?XDEBUG=1",
    "/api/debug", "/api/debug-info",
    "/actuator/env", "/actuator/configprops", "/actuator/heapdump",
    "/api/health?verbose=true", "/healthz?verbose=1",
    "/metrics", "/api/metrics",
    "/trace", "/api/trace",
    "/server-info", "/server-status",
]

ERROR_TRIGGER_PAYLOADS = [
    "?id='\"<>",
    "?id=" + "A" * 5000,
    "?id=%00",
    "?id[]=array",
    "?id={\"$gt\":\"\"}",
]

# Reject obvious dummy values in pattern matches.
DUMMY_HINTS = ("EXAMPLE", "DUMMY", "PLACEHOLDER", "YOUR_", "XXXX", "TEST")


def _is_dummy(value: str) -> bool:
    up = value.upper()
    return any(h in up for h in DUMMY_HINTS)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary, awam_steps = get_awam("env_leak")
    try:
        # 1. Pattern scan
        urls_to_scan = [target.base_url]
        state = get_state(config)
        if state:
            urls_to_scan += state.urls[:8]
        seen_secrets: set[str] = set()
        for url in urls_to_scan:
            r = client.get(url)
            if r is None:
                continue
            body = r.text or ""
            for rx, label, sev in SECRET_PATTERNS:
                m = rx.search(body)
                if not m:
                    continue
                value = m.group(0)
                if _is_dummy(value):
                    continue
                key = f"{label}:{value[:30]}"
                if key in seen_secrets:
                    continue
                seen_secrets.add(key)

                proof = ValidationProof(
                    method="regex+dummy-filter",
                    confirmed=False,  # tentative until manual verification
                    steps=[
                        f"GET {url}; body length={len(body)}.",
                        f"Pattern `{label}` cocok di body (signature: `{truncate(value, 60)}`).",
                        "Filter dummy/EXAMPLE/PLACEHOLDER lolos (bukan placeholder generik).",
                        "CATATAN: confidence 'tentative' — value belum diuji aktif/tidak. "
                        "Verifikasi rotasi & log audit di sisi cloud.",
                    ],
                    samples=[truncate(value, 80)],
                )
                findings.append(Finding(
                    module="env_leak",
                    title=f"Kebocoran kemungkinan {label}",
                    severity=sev,
                    description=(
                        f"Pola seperti {label} ditemukan di response publik. "
                        "Sudah lolos filter dummy. Jika benar live, attacker bisa "
                        "langsung memakai kredensial ini."
                    ),
                    target=url,
                    urls=[url],
                    evidence=truncate(value, 80),
                    cwe="CWE-200",
                    confidence="tentative",
                    remediation=(
                        "Pindahkan secret ke server-side env var (jangan bundle "
                        "ke build front-end). Rotasi kunci yang bocor segera, "
                        "audit log untuk penyalahgunaan, dan tambahkan secret "
                        "scanning di CI (mis. Gitleaks)."
                    ),
                    extra=build_extra(
                        proof=proof,
                        awam_steps=awam_steps,
                        awam_summary=awam_summary,
                    ),
                ))

        # 2. Stack trace
        for url in urls_to_scan[:3]:
            for payload in ERROR_TRIGGER_PAYLOADS:
                r = client.get(url + payload)
                if r is None:
                    continue
                body = r.text or ""
                for rx, label in STACKTRACE_PATTERNS:
                    m = rx.search(body)
                    if not m:
                        continue
                    proof = ValidationProof(
                        method="error-trigger+stack-pattern",
                        confirmed=True,
                        steps=[
                            f"Trigger: GET {url + payload}.",
                            f"Pola `{label}` muncul di response → stack trace bocor.",
                        ],
                        samples=[truncate(m.group(0), 150)],
                    )
                    findings.append(Finding(
                        module="env_leak",
                        title=f"Stack trace bocor: {label}",
                        severity=Severity.MEDIUM,
                        description=(
                            "Saat input tidak valid dikirim, server memunculkan "
                            "stack trace lengkap di response."
                        ),
                        target=url + payload,
                        urls=[url + payload],
                        evidence=truncate(m.group(0), 200),
                        cwe="CWE-209",
                        confidence="confirmed",
                        remediation=(
                            "Set environment ke `production`. Tampilkan generic error "
                            "ke user, kirim stack trace ke logging system saja."
                        ),
                        extra=build_extra(
                            proof=proof,
                            awam_steps=awam_steps,
                            awam_summary=awam_summary,
                        ),
                    ))
                    break
                else:
                    continue
                break

        # 3. Debug endpoints — with negative control
        ctrl_url = urljoin(
            target.origin + "/", f"cyberloka_{secrets.token_hex(4)}_404"
        )
        ctrl = client.get(ctrl_url)
        ctrl_len = len(ctrl.text or "") if ctrl is not None else 0
        for path in DEBUG_PATHS[:12]:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.get(url)
            if r is None or r.status_code >= 400:
                continue
            body = r.text or ""
            ctype = r.headers.get("Content-Type", "").lower()
            if abs(len(body) - ctrl_len) <= 32:
                continue  # same-as-404 echo
            interesting = (
                "json" in ctype or
                len(body) > 100 and (
                    "{" in body[:50] or "version" in body.lower()[:200]
                )
            )
            if not interesting:
                continue
            proof = ValidationProof(
                method="debug-endpoint+control-diff",
                confirmed=True,
                steps=[
                    f"GET {url} → status {r.status_code}, content-type={ctype}, len={len(body)}.",
                    f"Negative control {ctrl_url}: len={ctrl_len}, selisih={abs(len(body)-ctrl_len)}.",
                    "Body memuat marker JSON / 'version' → bukan halaman 404 generik.",
                ],
                samples=[truncate(body, 150)],
            )
            findings.append(Finding(
                module="env_leak",
                title=f"Endpoint debug/internal terbuka: {path}",
                severity=Severity.HIGH,
                description=(
                    "Endpoint debug/diagnostic dapat diakses publik dan respons-nya "
                    "berbeda dari path-404 kontrol."
                ),
                target=url,
                urls=[url],
                evidence=f"HTTP {r.status_code}, ctype={ctype}, len={len(body)}",
                cwe="CWE-489",
                confidence="firm",
                remediation=(
                    "Matikan debug endpoint di production atau lindungi dengan "
                    "auth + IP allowlist. Untuk Spring: `management.endpoints.web."
                    "exposure.include=health` saja."
                ),
                extra=build_extra(
                    proof=proof,
                    awam_steps=awam_steps,
                    awam_summary=awam_summary,
                ),
            ))
            if sum(1 for f in findings if f.module == "env_leak"
                   and "debug/internal" in f.title) >= 3:
                break
    finally:
        client.close()
    return findings
