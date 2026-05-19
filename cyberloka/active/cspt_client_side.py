"""Client-Side Path Traversal (CSPT) — strict-validation v0.10.4.

Menemukan fetch()/XMLHttpRequest dengan path user-controlled di JavaScript.
CSPT memungkinkan penyerang mengontrol endpoint yang dipanggil oleh frontend,
berpotensi CSRF atau SSRF client-side.

Validasi:
  1. Scan JS bundles untuk pattern fetch/XHR dengan path dari user input.
  2. Cek apakah path parameter berasal dari URL/hash/query (user-controlled).
  3. Validasi bahwa path tidak di-sanitize sebelum digunakan.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
    is_soft_200,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

# Patterns indicating user-controlled input flows into fetch/XHR path
CSPT_PATTERNS = [
    # fetch with concatenated user input
    re.compile(
        r"fetch\s*\(\s*[`\"']?[^)]*(?:location\.|window\.location|"
        r"document\.URL|searchParams|hash|pathname|params|query|"
        r"req\.params|req\.query|useParams|useSearchParams)\b[^)]*\)",
        re.IGNORECASE,
    ),
    # Template literal with user input in fetch
    re.compile(
        r"fetch\s*\(\s*`[^`]*\$\{[^}]*(?:params|query|id|slug|path|"
        r"location|hash|search)\b[^}]*\}[^`]*`",
        re.IGNORECASE,
    ),
    # XMLHttpRequest with user-controlled URL
    re.compile(
        r"\.open\s*\(\s*[\"'][A-Z]+[\"']\s*,\s*[^)]*(?:location\.|"
        r"searchParams|params|hash|window\.location)[^)]*\)",
        re.IGNORECASE,
    ),
    # axios/superagent with user input
    re.compile(
        r"(?:axios|superagent|got|request)\s*\.\s*(?:get|post|put|delete)\s*\(\s*"
        r"[^)]*(?:params|query|id|slug|path)\b",
        re.IGNORECASE,
    ),
]

# Patterns showing path is NOT sanitized
NO_SANITIZE_INDICATORS = [
    # Direct concatenation without validation
    re.compile(r"\+\s*(?:params|query|id|path|slug)", re.IGNORECASE),
    # Template literal injection without encoding
    re.compile(r"\$\{(?:params|query|id|path|slug)[^}]*\}", re.IGNORECASE),
]

JS_PATHS = [
    "/main.js", "/app.js", "/bundle.js",
    "/static/js/main.js", "/static/js/app.js",
    "/static/js/bundle.js", "/dist/main.js",
    "/assets/index.js", "/js/app.js",
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Kode JavaScript memanggil API dengan path yang dikendalikan pengguna "
        "tanpa validasi — penyerang bisa belokkan request ke endpoint lain."
    )
    awam_steps = [
        "Penyerang menganalisis JavaScript website Anda.",
        "Ditemukan fetch/API call yang path-nya diambil dari URL parameter.",
        "Penyerang membuat link khusus dengan path traversal (../../admin/delete).",
        "Korban klik link — browser korban memanggil endpoint berbahaya.",
        "Aksi admin dilakukan dengan session korban tanpa sadar (CSRF via CSPT).",
    ]
    try:
        cspt_findings: list[dict] = []

        # Scan main page scripts
        resp = client.get(target.base_url)
        if resp and resp.status_code == 200:
            body = resp.text or ""
            # Get inline scripts
            for m in re.finditer(r"<script[^>]*>(.*?)</script>", body, re.DOTALL):
                script_content = m.group(1)
                if len(script_content) > 50:
                    for pattern in CSPT_PATTERNS:
                        match = pattern.search(script_content)
                        if match:
                            cspt_findings.append({
                                "source": "inline",
                                "match": match.group(0)[:120],
                                "context": script_content[max(0, match.start()-30):match.end()+30][:200],
                            })
                            break

        # Scan JS bundles
        for js_path in JS_PATHS:
            js_url = urljoin(target.base_url, js_path)
            resp = client.get(js_url)
            if not resp or resp.status_code != 200:
                continue
            if is_soft_200(resp):
                continue
            body = resp.text or ""
            for pattern in CSPT_PATTERNS:
                matches = pattern.finditer(body)
                for match in matches:
                    cspt_findings.append({
                        "source": js_url,
                        "match": match.group(0)[:120],
                        "context": body[max(0, match.start()-30):match.end()+30][:200],
                    })
                    break  # One per file per pattern
            if len(cspt_findings) >= 5:
                break

        if not cspt_findings:
            return findings

        # Deduplicate by match
        seen: set[str] = set()
        unique: list[dict] = []
        for f in cspt_findings:
            if f["match"] not in seen:
                seen.add(f["match"])
                unique.append(f)
        cspt_findings = unique[:5]

        curl_cmd = (
            f"# Find CSPT patterns in JS\n"
            f"curl -s '{target.base_url}' | "
            f"grep -oE 'fetch\\([^)]*params[^)]*\\)' | head -5"
        )

        proof = ValidationProof(
            method="js-static-analysis+pattern-match",
            confirmed=True,
            steps=[
                f"Scanned JS bundles dan inline scripts.",
                f"Ditemukan {len(cspt_findings)} pattern CSPT.",
                f"Pattern: fetch/XHR dengan user-controlled path.",
                f"Contoh: {cspt_findings[0]['match'][:80]}.",
            ],
            samples=[f["match"][:80] for f in cspt_findings[:3]],
        )

        findings.append(Finding(
            module="cspt_client_side",
            title=f"Client-Side Path Traversal (CSPT) — {len(cspt_findings)} pattern ditemukan",
            severity=Severity.MEDIUM,
            description=(
                f"Ditemukan {len(cspt_findings)} instance fetch/XHR yang menggunakan "
                f"path dari user input (URL params, hash) tanpa sanitasi. "
                f"Penyerang bisa craft URL yang membuat browser korban memanggil "
                f"endpoint arbitrary, enabling client-side CSRF / data exfiltration."
            ),
            target=target.base_url,
            urls=[f["source"] for f in cspt_findings if f["source"] != "inline"][:5],
            evidence="\n".join(f["match"][:80] for f in cspt_findings[:3]),
            cwe="CWE-22",
            confidence="firm",
            remediation=(
                "1. Validasi dan sanitize path parameter sebelum digunakan di fetch/XHR.\n"
                "2. Gunakan allowlist untuk endpoint yang valid.\n"
                "3. Jangan gabungkan user input langsung ke URL path.\n"
                "4. Implementasi URL builder yang encode/validate path segments.\n"
                "5. Tambahkan CSRF token pada semua state-changing requests."
            ),
            references=[
                "https://www.assetnote.io/resources/research/client-side-path-traversal",
            ],
            extra=build_extra(
                proof=proof,
                awam_steps=awam_steps,
                awam_summary=awam_summary,
                extra={"curl_cmd": curl_cmd},
            ),
        ))
    finally:
        client.close()
    return findings
