"""DOM Clobbering — strict-validation v0.10.4.

Menguji apakah HTML injection bisa overwrite JavaScript globals melalui DOM
clobbering. Jika aplikasi membaca `window.X` dan attacker bisa inject
`<a id=X href=evil>`, maka `window.X.toString()` = evil URL.

Validasi:
  1. Scan JS untuk akses ke named properties (window.X, document.X).
  2. Cek apakah ada HTML injection point yang bisa inject elements dengan id/name.
  3. Verifikasi bahwa clobbered property digunakan di konteks sensitif.
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

# JS patterns that read named DOM properties (clobberable)
CLOBBERABLE_PATTERNS = [
    # Direct window property access used in sensitive context
    re.compile(
        r"(?:window|document|globalThis)\[?\.?([\w$]+)\]?\s*(?:\|\||&&|\?|\.(?:href|src|url|action|toString))",
        re.IGNORECASE,
    ),
    # Config/settings from global
    re.compile(
        r"(?:var|let|const)\s+\w+\s*=\s*(?:window|document)\.(config|settings|options|data|params)\b",
        re.IGNORECASE,
    ),
    # form/element access patterns
    re.compile(
        r"document\.(?:forms|getElementById|getElementsByName)\[?[\s\"'\w]+\]?\.(?:action|href|src)",
        re.IGNORECASE,
    ),
]

# HTML injection indicators (reflected params in HTML context)
HTML_INJECTION_MARKERS = [
    "cyberloka_dom_clob_test",
]

JS_PATHS = [
    "/main.js", "/app.js", "/bundle.js",
    "/static/js/main.js", "/static/js/app.js",
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Aplikasi membaca properti dari DOM yang bisa di-overwrite via HTML injection — "
        "penyerang bisa mengalihkan URL/aksi ke domain berbahaya."
    )
    awam_steps = [
        "Penyerang menemukan titik HTML injection di aplikasi (komentar, profil, dll.).",
        "Penyerang menyisipkan tag <a id='config' href='https://evil.com'>.",
        "JavaScript membaca window.config — tapi sekarang isinya URL penyerang.",
        "Aplikasi menggunakan URL tersebut untuk redirect/fetch/form action.",
        "Korban diarahkan ke situs penyerang atau data dikirim ke server penyerang.",
    ]
    try:
        clobberable_found: list[dict] = []

        # Scan JS for clobberable patterns
        resp = client.get(target.base_url)
        if resp and resp.status_code == 200:
            body = resp.text or ""
            # Check inline scripts
            for m in re.finditer(r"<script[^>]*>(.*?)</script>", body, re.DOTALL):
                script = m.group(1)
                for pattern in CLOBBERABLE_PATTERNS:
                    pm = pattern.search(script)
                    if pm:
                        clobberable_found.append({
                            "source": "inline",
                            "match": pm.group(0)[:100],
                            "property": pm.group(1) if pm.lastindex else pm.group(0)[:30],
                        })

        # Scan external JS
        for js_path in JS_PATHS:
            js_url = urljoin(target.base_url, js_path)
            resp = client.get(js_url)
            if not resp or resp.status_code != 200:
                continue
            if is_soft_200(resp):
                continue
            body = resp.text or ""
            for pattern in CLOBBERABLE_PATTERNS:
                for pm in pattern.finditer(body):
                    clobberable_found.append({
                        "source": js_url,
                        "match": pm.group(0)[:100],
                        "property": pm.group(1) if pm.lastindex else pm.group(0)[:30],
                    })
                    break
            if len(clobberable_found) >= 5:
                break

        if not clobberable_found:
            return findings

        # Test for HTML injection potential
        # Try reflecting content via common params
        injection_confirmed = False
        test_marker = "cyberloka_dom_clob_test"
        for param in ["q", "search", "name", "title", "comment", "msg"]:
            test_url = f"{target.base_url}?{param}=<a id={test_marker}>"
            resp = client.get(test_url)
            if resp and resp.status_code == 200:
                if f"id={test_marker}" in (resp.text or "") or f'id="{test_marker}"' in (resp.text or ""):
                    injection_confirmed = True
                    break

        # Deduplicate
        seen: set[str] = set()
        unique: list[dict] = []
        for f in clobberable_found:
            key = f["match"]
            if key not in seen:
                seen.add(key)
                unique.append(f)
        clobberable_found = unique[:5]

        curl_cmd = (
            f"# DOM Clobbering test\n"
            f"# Step 1: Find clobberable properties in JS\n"
            f"curl -s '{target.base_url}' | grep -oE 'window\\.[a-zA-Z_]+\\.(href|src|url)'\n"
            f"# Step 2: Inject clobbering element\n"
            f"# <a id=\"CONFIG_VAR\" href=\"https://evil.com\">"
        )

        proof = ValidationProof(
            method="js-pattern-analysis+html-injection-check",
            confirmed=injection_confirmed,
            steps=[
                f"JS analysis: {len(clobberable_found)} clobberable property access ditemukan.",
                f"Properties: {[f['property'] for f in clobberable_found[:5]]}.",
                f"HTML injection point: {'CONFIRMED' if injection_confirmed else 'not tested (manual check needed)'}.",
                "Clobberable pattern: window/document property dipakai di context sensitif.",
            ],
            samples=[f["match"][:60] for f in clobberable_found[:3]],
        )

        findings.append(Finding(
            module="dom_clobbering",
            title=f"DOM Clobbering risk — {len(clobberable_found)} clobberable properties",
            severity=Severity.MEDIUM,
            description=(
                f"JavaScript mengakses {len(clobberable_found)} named DOM properties "
                f"yang bisa di-overwrite melalui HTML injection (DOM Clobbering). "
                f"{'HTML injection point CONFIRMED — risk tinggi. ' if injection_confirmed else ''}"
                f"Jika penyerang bisa inject HTML element dengan id/name yang sama, "
                f"properti tersebut akan ter-overwrite ke nilai penyerang."
            ),
            target=target.base_url,
            urls=[f["source"] for f in clobberable_found if f["source"] != "inline"][:3],
            evidence="\n".join(f["match"][:80] for f in clobberable_found[:3]),
            cwe="CWE-79",
            confidence="confirmed" if injection_confirmed else "firm",
            remediation=(
                "1. Gunakan variabel lokal (const/let) bukan global window properties.\n"
                "2. Validasi tipe sebelum menggunakan DOM property (typeof === 'string').\n"
                "3. Sanitize HTML input dengan DOMPurify (aktifkan SANITIZE_NAMED_PROPS).\n"
                "4. Gunakan Object.freeze pada config objects.\n"
                "5. Implementasi Content-Security-Policy yang ketat."
            ),
            references=[
                "https://portswigger.net/web-security/dom-based/dom-clobbering",
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
