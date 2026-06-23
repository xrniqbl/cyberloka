"""Firebase Remote Config Public Access — strict-validation v0.10.4.

Probe Firebase Remote Config API untuk akses publik tanpa autentikasi.
Firebase Remote Config yang public bisa bocorkan feature flags, API keys,
secret configurations, dan backend URLs.

Validasi:
  1. Temukan Firebase project ID (dari JS SDK init, config, atau /__/firebase/init.json).
  2. Probe Remote Config REST API.
  3. Jika response berisi config data → leak confirmed.
  4. Double-confirm dengan fetch kedua.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
    is_soft_200, looks_like_html_shell,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

# Firebase project patterns in JS/HTML
FIREBASE_PROJECT_RE = re.compile(
    r"(?:projectId|project_id|firebase.*?project)\s*[=:]\s*[\"']([a-z0-9\-]{6,30})[\"']",
    re.IGNORECASE,
)

FIREBASE_CONFIG_RE = re.compile(
    r"apiKey\s*:\s*[\"']AIza[A-Za-z0-9_\-]{35}[\"']",
)

# Firebase hosting init
FIREBASE_INIT_PATHS = [
    "/__/firebase/init.json",
    "/__/firebase/init.js",
]

# Remote Config REST API format
REMOTE_CONFIG_URL = "https://firebaseremoteconfig.googleapis.com/v1/projects/{project_id}/remoteConfig"

# Alternative: Firebase Remote Config fetch endpoint
REMOTE_CONFIG_FETCH_URL = "https://firebaseremoteconfig.googleapis.com/v1/projects/{project_id}/namespaces/firebase:fetch"


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "Konfigurasi Firebase Remote Config terbuka publik — penyerang bisa "
        "membaca feature flags, kunci API internal, dan konfigurasi backend Anda."
    )
    awam_steps = [
        "Penyerang menemukan Firebase Project ID dari source code website.",
        "Penyerang mengakses Firebase Remote Config API langsung.",
        "Server membalas dengan seluruh konfigurasi (feature flags, API keys).",
        "Penyerang menemukan URL backend internal dan kunci rahasia.",
        "Penyerang gunakan informasi tersebut untuk serangan lanjutan.",
    ]
    try:
        project_ids: set[str] = set()

        # Step 1: Find Firebase project ID
        resp = client.get(target.base_url)
        if resp and resp.status_code == 200:
            body = resp.text or ""
            for m in FIREBASE_PROJECT_RE.finditer(body):
                project_ids.add(m.group(1))

        # Check Firebase init endpoint
        for init_path in FIREBASE_INIT_PATHS:
            url = urljoin(target.base_url, init_path)
            resp = client.get(url)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    pid = data.get("projectId") or data.get("project_id")
                    if pid:
                        project_ids.add(pid)
                except Exception:
                    body = resp.text or ""
                    for m in FIREBASE_PROJECT_RE.finditer(body):
                        project_ids.add(m.group(1))

        if not project_ids:
            return findings

        # Step 2: Probe Remote Config API for each project
        for project_id in list(project_ids)[:3]:
            rc_url = REMOTE_CONFIG_URL.format(project_id=project_id)
            resp = client.get(rc_url)

            if resp and resp.status_code == 200:
                body = resp.text or ""
                if len(body) < 10:
                    continue
                # Check if it contains actual config parameters
                if '"parameters"' in body or '"conditions"' in body or '"parameterGroups"' in body:
                    # Double confirm
                    resp2 = client.get(rc_url)
                    if not resp2 or resp2.status_code != 200:
                        continue

                    curl_cmd = (
                        f"# Firebase Remote Config leak\n"
                        f"curl -s '{rc_url}' | python3 -m json.tool | head -50"
                    )

                    proof = ValidationProof(
                        method="firebase-discovery+remote-config-fetch+double-confirm",
                        confirmed=True,
                        steps=[
                            f"Firebase project ID ditemukan: {project_id}.",
                            f"GET {rc_url} → 200 OK.",
                            "Response berisi 'parameters' / 'conditions' — config valid.",
                            "Double-confirm: fetch kedua konsisten.",
                        ],
                        samples=[f"project_id={project_id}", f"body_snippet={body[:100]}"],
                    )

                    findings.append(Finding(
                        module="firebase_remote_config",
                        title=f"Firebase Remote Config terbuka publik: {project_id}",
                        severity=Severity.HIGH,
                        description=(
                            f"Firebase Remote Config untuk project {project_id} "
                            f"bisa diakses tanpa autentikasi di {rc_url}. "
                            f"Data yang terekspos mungkin berisi feature flags, "
                            f"API keys, backend URLs, dan konfigurasi sensitif lainnya."
                        ),
                        target=rc_url,
                        urls=[rc_url],
                        evidence=f"project={project_id}, body_len={len(body)}",
                        cwe="CWE-200",
                        confidence="confirmed",
                        remediation=(
                            "1. Set Firebase Remote Config ke require authentication.\n"
                            "2. Restrict API key dengan HTTP referrer restrictions.\n"
                            "3. Jangan simpan secrets di Remote Config — gunakan Secret Manager.\n"
                            "4. Enable IAM conditions pada Remote Config API.\n"
                            "5. Audit isi Remote Config — hapus data sensitif."
                        ),
                        references=[
                            "https://firebase.google.com/docs/remote-config/get-started",
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
