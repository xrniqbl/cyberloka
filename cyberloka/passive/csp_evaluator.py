"""Evaluate strength of Content-Security-Policy header."""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig


def _parse_csp(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        toks = part.split()
        out[toks[0].lower()] = toks[1:]
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        r = client.get(target.base_url)
        if r is None:
            return findings
        csp = r.headers.get("Content-Security-Policy") or r.headers.get("content-security-policy")
        if not csp:
            return findings  # `headers` module sudah menangani missing CSP
        parsed = _parse_csp(csp)
        problems: list[str] = []
        sev = Severity.LOW
        for directive in ("default-src", "script-src", "style-src"):
            vals = parsed.get(directive, [])
            if not vals:
                continue
            joined = " ".join(vals)
            if "'unsafe-inline'" in vals:
                problems.append(f"{directive} mengizinkan 'unsafe-inline'")
                sev = Severity.MEDIUM
            if "'unsafe-eval'" in vals:
                problems.append(f"{directive} mengizinkan 'unsafe-eval'")
                sev = Severity.MEDIUM
            if "*" in vals:
                problems.append(f"{directive} memuat wildcard `*`")
                sev = Severity.MEDIUM
            if "data:" in vals and directive == "script-src":
                problems.append(f"{directive} mengizinkan `data:` (script bisa di-inline)")
                sev = Severity.HIGH
            if "'strict-dynamic'" in vals and not any(t.startswith("'nonce-") or t.startswith("'sha")
                                                       for t in vals):
                problems.append(f"{directive} pakai 'strict-dynamic' tanpa nonce/hash")
                sev = Severity.MEDIUM
        if "object-src" not in parsed:
            problems.append("`object-src` tidak diset (idealnya 'none')")
        if "frame-ancestors" not in parsed:
            problems.append("`frame-ancestors` tidak diset (clickjacking guard)")
        if "base-uri" not in parsed:
            problems.append("`base-uri` tidak diset (rentan base injection)")

        if problems:
            findings.append(Finding(
                module="csp_evaluator",
                title="Content-Security-Policy lemah / longgar",
                severity=sev,
                description=("Header CSP ada tapi memuat directive yang melemahkan proteksi. "
                             "CSP yang baik memblokir XSS bahkan jika ada bug di template."),
                target=target.base_url,
                evidence=csp,
                cwe="CWE-1021",
                remediation=("Hapus 'unsafe-inline' & 'unsafe-eval'. Gunakan nonce per-request "
                             "atau hash. Set `object-src 'none'`, `frame-ancestors 'self'`, "
                             "`base-uri 'self'`. Test dengan CSP Evaluator (Google)."),
                references=["https://csp-evaluator.withgoogle.com/"],
                extra={"issues": problems},
            ))
    finally:
        client.close()
    return findings
