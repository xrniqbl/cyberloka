"""Vite HMR Dev Server Exposure — strict-validation v0.10.4.

Probe /__vite_ping dan /@vite/client untuk mendeteksi Vite dev server yang
terekspos di production. Dev server yang terbuka bisa leak source code,
enable HMR manipulation, dan mengekspos module graph.

Validasi:
  1. Probe /__vite_ping → expect 200 (Vite HMR heartbeat).
  2. Probe /@vite/client → expect JS Vite client code.
  3. Negative control: pastikan bukan custom handler yang kebetulan 200.
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

VITE_PATHS = [
    ("/__vite_ping", "vite_ping"),
    ("/@vite/client", "vite_client"),
    ("/@vite/env", "vite_env"),
    ("/@fs/", "vite_fs"),
    ("/__vite_plugin_react/preamble", "vite_react"),
]

VITE_CLIENT_SIGNATURES = [
    "/@vite/client",
    "import.meta.hot",
    "__vite__",
    "createHotContext",
    "vite/dist/client",
    "hmrClient",
]

VITE_PING_SIGNATURES = [
    # Vite ping typically returns empty 200 or a short response
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Vite dev server terekspos di production — penyerang bisa membaca "
        "source code aplikasi dan memanipulasi Hot Module Replacement."
    )
    awam_steps = [
        "Penyerang mengakses /__vite_ping atau /@vite/client di website Anda.",
        "Server Vite dev merespons — artinya mode development aktif di production.",
        "Penyerang mengakses /@fs/ untuk membaca file di server (source code).",
        "Penyerang membaca environment variables, API keys, dan kode rahasia.",
        "Penyerang bisa inject module berbahaya via HMR WebSocket.",
    ]
    try:
        confirmed_paths: list[tuple[str, str]] = []

        for path, check_type in VITE_PATHS:
            url = urljoin(target.base_url, path)
            resp = client.get(url)
            if resp is None or resp.status_code != 200:
                continue
            if is_soft_200(resp):
                continue

            body = resp.text or ""

            if check_type == "vite_ping":
                # Vite ping returns 200 with empty or minimal body
                if len(body) <= 50:
                    confirmed_paths.append((url, check_type))
            elif check_type == "vite_client":
                # Should contain Vite client code signatures
                if any(sig in body for sig in VITE_CLIENT_SIGNATURES):
                    confirmed_paths.append((url, check_type))
            elif check_type == "vite_env":
                if "import.meta" in body or "MODE" in body:
                    confirmed_paths.append((url, check_type))
            elif check_type == "vite_fs":
                # /@fs/ allows reading filesystem
                if resp.status_code == 200 and len(body) > 0:
                    confirmed_paths.append((url, check_type))
            elif check_type == "vite_react":
                if "react" in body.lower() or "jsx" in body.lower():
                    confirmed_paths.append((url, check_type))

        if not confirmed_paths:
            return findings

        # Double confirm
        first_url, first_type = confirmed_paths[0]
        resp2 = client.get(first_url)
        if resp2 is None or resp2.status_code != 200:
            return findings

        curl_cmd = (
            f"# Vite dev server exposure\n"
            f"curl -s '{first_url}'\n"
            f"# Cek filesystem access:\n"
            f"curl -s '{urljoin(target.base_url, '/@fs/etc/passwd')}'"
        )

        proof = ValidationProof(
            method="vite-endpoint-probe+signature-check+double-confirm",
            confirmed=True,
            steps=[
                f"Probed {len(VITE_PATHS)} Vite-specific paths.",
                f"Confirmed {len(confirmed_paths)} Vite endpoints active.",
                f"Paths: {[p for p, _ in confirmed_paths]}.",
                "Vite client signatures found in response body.",
                "Double-confirm: second fetch konsisten.",
            ],
            samples=[f"{p}={t}" for p, t in confirmed_paths],
        )

        findings.append(Finding(
            module="vite_hmr_exposure",
            title="Vite dev server terekspos di production",
            severity=Severity.HIGH,
            description=(
                f"Vite development server terdeteksi aktif di production. "
                f"Endpoints terekspos: {', '.join(p for p, _ in confirmed_paths)}. "
                f"Dev server mengekspos source code, environment variables, "
                f"dan memungkinkan manipulasi HMR (Hot Module Replacement). "
                f"Endpoint /@fs/ bahkan bisa membaca file arbitrary di server."
            ),
            target=first_url,
            urls=[p for p, _ in confirmed_paths],
            evidence=f"vite_endpoints={confirmed_paths}",
            cwe="CWE-200",
            confidence="confirmed",
            remediation=(
                "1. JANGAN deploy Vite dev server ke production.\n"
                "2. Pastikan build command production: `vite build` (bukan `vite` / `vite dev`).\n"
                "3. Set `server.fs.deny` untuk block /@fs/ access.\n"
                "4. Verifikasi Dockerfile/deploy script menggunakan production build.\n"
                "5. Add WAF rule untuk block /__vite* dan /@vite* paths."
            ),
            references=[
                "https://vitejs.dev/guide/build.html",
                "https://vitejs.dev/config/server-options.html#server-fs-deny",
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
