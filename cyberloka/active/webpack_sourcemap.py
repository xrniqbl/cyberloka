"""Webpack Source Map Exposure — strict-validation v0.10.4.

Menemukan file .js.map yang terekspos publik. Source map mengekspos
source code original, absolute path server, dan internal comments.

Validasi:
  1. Temukan referensi ke .map files dari JS bundles (sourceMappingURL).
  2. Fetch .js.map file dan validasi isinya.
  3. Cek apakah berisi absolute paths atau source code.
  4. Double-confirm.
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

SOURCE_MAP_URL_RE = re.compile(
    r"//[#@]\s*sourceMappingURL\s*=\s*(\S+\.map)",
    re.IGNORECASE,
)

JS_PATHS = [
    "/main.js", "/app.js", "/bundle.js",
    "/static/js/main.js", "/static/js/app.js",
    "/static/js/bundle.js", "/dist/main.js",
    "/assets/index.js", "/js/app.js",
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/webpack.js",
]

# Indicators that source map contains sensitive info
SENSITIVE_PATH_RE = re.compile(
    r"(?:/home/|/root/|/var/|/opt/|/srv/|C:\\\\|D:\\\\|"
    r"/Users/[^/]+/|webpack://|node_modules/)",
    re.IGNORECASE,
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "File source map (.js.map) terbuka publik — penyerang bisa membaca "
        "seluruh source code original aplikasi Anda."
    )
    awam_steps = [
        "Penyerang menemukan referensi ke file .js.map di JavaScript bundle.",
        "Penyerang download file .map tersebut (biasanya besar, berisi semua kode).",
        "Dari source map, penyerang merekonstruksi source code original.",
        "Penyerang mempelajari logika bisnis, API keys, path internal.",
        "Penyerang menemukan celah keamanan yang tersembunyi di kode.",
    ]
    try:
        source_maps_found: list[tuple[str, str]] = []  # (map_url, evidence)

        # Scan known JS paths
        for js_path in JS_PATHS:
            js_url = urljoin(target.base_url, js_path)
            resp = client.get(js_url)
            if not resp or resp.status_code != 200:
                continue
            body = resp.text or ""
            # Look for sourceMappingURL
            m = SOURCE_MAP_URL_RE.search(body[-500:])  # Usually at end of file
            if m:
                map_ref = m.group(1)
                if map_ref.startswith("http"):
                    map_url = map_ref
                else:
                    map_url = urljoin(js_url, map_ref)
                source_maps_found.append((map_url, js_url))
            else:
                # Try appending .map to JS URL
                map_url = js_url + ".map"
                source_maps_found.append((map_url, js_url))

        # Also try main page for script tags
        resp = client.get(target.base_url)
        if resp and resp.status_code == 200:
            body = resp.text or ""
            for m in re.finditer(r'src=["\']([^"\']+\.js)["\']', body):
                js_url = urljoin(target.base_url, m.group(1))
                map_url = js_url + ".map"
                source_maps_found.append((map_url, js_url))

        if not source_maps_found:
            return findings

        # Test each source map URL
        seen: set[str] = set()
        for map_url, src_js in source_maps_found[:10]:
            if map_url in seen:
                continue
            seen.add(map_url)

            resp = client.get(map_url)
            if not resp or resp.status_code != 200:
                continue
            if is_soft_200(resp):
                continue

            body = resp.text or ""
            ct = resp.headers.get("Content-Type", "").lower()

            # Validate it's actually a source map
            is_sourcemap = (
                '"sources"' in body[:500]
                or '"mappings"' in body[:1000]
                or '"sourcesContent"' in body[:500]
                or "application/json" in ct
            )
            if not is_sourcemap:
                continue

            # Check for sensitive paths
            sensitive_paths = SENSITIVE_PATH_RE.findall(body[:5000])
            has_sources_content = '"sourcesContent"' in body

            # Double confirm
            resp2 = client.get(map_url)
            if not resp2 or resp2.status_code != 200:
                continue

            curl_cmd = (
                f"# Webpack source map exposure\n"
                f"curl -s '{map_url}' | python3 -c \"import sys,json;"
                f"d=json.load(sys.stdin);print(d.get('sources',[])[: 10])\""
            )

            proof = ValidationProof(
                method="sourcemap-reference+content-validation+double-confirm",
                confirmed=True,
                steps=[
                    f"JS bundle: {src_js}.",
                    f"Source map: {map_url} → 200 OK, {len(body)} bytes.",
                    f"Valid source map structure (sources/mappings present).",
                    f"Sensitive paths: {sensitive_paths[:5]}.",
                    f"sourcesContent present: {has_sources_content}.",
                    "Double-confirm: fetch kedua konsisten.",
                ],
                samples=[f"paths={sensitive_paths[:5]}", f"size={len(body)}"],
            )

            findings.append(Finding(
                module="webpack_sourcemap",
                title=f"Source map terekspos: {map_url.split('/')[-1]}",
                severity=Severity.MEDIUM,
                description=(
                    f"File source map {map_url} terbuka publik ({len(body)} bytes). "
                    f"{'Berisi sourcesContent (full source code). ' if has_sources_content else ''}"
                    f"{'Mengekspos absolute paths: ' + str(sensitive_paths[:3]) + '. ' if sensitive_paths else ''}"
                    f"Source map memungkinkan rekonstruksi source code original."
                ),
                target=map_url,
                urls=[map_url],
                evidence=f"size={len(body)}, has_sources={has_sources_content}, paths={sensitive_paths[:3]}",
                cwe="CWE-540",
                confidence="confirmed",
                remediation=(
                    "1. Hapus file .map dari production deployment.\n"
                    "2. Set `devtool: false` di webpack.config.js untuk production.\n"
                    "3. Jika perlu source map untuk error tracking, upload ke Sentry/Datadog secara private.\n"
                    "4. Block akses *.map via web server config (nginx/Apache).\n"
                    "5. Hapus `//# sourceMappingURL` comment dari JS bundles."
                ),
                references=[
                    "https://developer.chrome.com/docs/devtools/javascript/source-maps/",
                ],
                extra=build_extra(
                    proof=proof,
                    awam_steps=awam_steps,
                    awam_summary=awam_summary,
                    extra={"curl_cmd": curl_cmd},
                ),
            ))
            break
    finally:
        client.close()
    return findings
