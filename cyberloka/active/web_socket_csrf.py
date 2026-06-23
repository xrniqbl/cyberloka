"""WebSocket CSRF (Cross-Site WebSocket Hijacking) — strict-validation v0.10.4.

Menguji apakah WebSocket upgrade diterima tanpa validasi Origin header.
Tanpa cek Origin, penyerang dari domain lain bisa membuka WebSocket ke server
menggunakan cookie/session korban.

Validasi:
  1. Temukan WebSocket endpoint (ws:// atau wss://).
  2. Kirim upgrade request dengan Origin: https://evil.example.
  3. Jika server menerima upgrade (101) → tidak ada Origin validation.
  4. Double-confirm dengan Origin berbeda.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from cyberloka.core import (
    Finding, HttpClient, Severity, Target, ValidationProof, build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

WS_PATHS = [
    "/ws", "/ws/", "/websocket", "/socket",
    "/socket.io/", "/sockjs/", "/cable",
    "/api/ws", "/api/websocket", "/realtime",
    "/hub", "/signalr", "/live",
]

# WebSocket URL patterns in JS
WS_URL_RE = re.compile(
    r"(?:wss?://[^\s\"'<>]+|new\s+WebSocket\s*\(\s*[\"']([^\"']+)[\"'])",
    re.IGNORECASE,
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary = (
        "WebSocket server menerima koneksi dari domain mana pun — penyerang "
        "bisa membajak koneksi real-time korban dari halaman jahat."
    )
    awam_steps = [
        "Penyerang membuat halaman jahat di domain miliknya.",
        "Halaman jahat membuka WebSocket ke server Anda (pakai cookie korban).",
        "Server tidak cek asal (Origin) — koneksi diterima.",
        "Penyerang membaca semua pesan real-time korban (chat, notifikasi, data).",
        "Penyerang juga bisa mengirim pesan sebagai korban.",
    ]
    try:
        ws_endpoints: list[str] = []

        # Discover WS endpoints from JS
        resp = client.get(target.base_url)
        if resp and resp.status_code == 200:
            body = resp.text or ""
            for m in WS_URL_RE.finditer(body):
                ws_url = m.group(1) or m.group(0)
                if ws_url.startswith("ws"):
                    # Convert to http for upgrade test
                    http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
                    ws_endpoints.append(http_url)

        # Add guessed paths
        parsed = urlparse(target.base_url)
        for path in WS_PATHS:
            ws_endpoints.append(urljoin(target.base_url, path))

        if not ws_endpoints:
            return findings

        evil_origin = "https://evil.cyberloka-test.example"

        for ws_url in ws_endpoints[:10]:
            # Attempt WebSocket upgrade with evil Origin
            upgrade_headers = {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
                "Origin": evil_origin,
            }

            resp = client.get(ws_url, headers=upgrade_headers)
            if resp is None:
                continue

            # Check for successful upgrade or non-rejected response
            status = resp.status_code

            # 101 = Switching Protocols (upgrade accepted)
            # Some servers return 200 for socket.io polling
            if status == 101:
                # WebSocket upgrade accepted with evil origin → vulnerable
                pass
            elif status == 200:
                # Could be socket.io long-polling — check response
                body = (resp.text or "").lower()
                if "websocket" not in body and "sid" not in body:
                    continue
            elif status == 400:
                body = (resp.text or "").lower()
                if "origin" in body or "not allowed" in body or "forbidden" in body:
                    continue  # Origin validation working
                # 400 might be other issues, skip
                continue
            elif status in (403, 401):
                continue  # Origin rejected or auth required
            else:
                continue

            # Double confirm with different evil origin
            evil_origin2 = "https://attacker.cyberloka-test.example"
            upgrade_headers2 = dict(upgrade_headers)
            upgrade_headers2["Origin"] = evil_origin2
            resp2 = client.get(ws_url, headers=upgrade_headers2)
            if resp2 is None:
                continue
            if resp2.status_code in (403, 401):
                continue  # Intermittent, skip
            if resp2.status_code not in (101, 200):
                continue

            curl_cmd = (
                f"# WebSocket CSRF test — evil Origin\n"
                f"curl -s -i '{ws_url}' \\\n"
                f"  -H 'Upgrade: websocket' \\\n"
                f"  -H 'Connection: Upgrade' \\\n"
                f"  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \\\n"
                f"  -H 'Sec-WebSocket-Version: 13' \\\n"
                f"  -H 'Origin: https://evil.example'"
            )

            proof = ValidationProof(
                method="ws-upgrade+evil-origin+double-confirm",
                confirmed=True,
                steps=[
                    f"WebSocket endpoint: {ws_url}.",
                    f"Upgrade request dengan Origin: {evil_origin} → {status}.",
                    f"Upgrade request dengan Origin: {evil_origin2} → {resp2.status_code}.",
                    "Server TIDAK menolak berdasarkan Origin.",
                    "Kesimpulan: Cross-Site WebSocket Hijacking possible.",
                ],
                samples=[f"status_evil1={status}", f"status_evil2={resp2.status_code}"],
            )

            findings.append(Finding(
                module="web_socket_csrf",
                title="WebSocket menerima koneksi tanpa validasi Origin (CSWSH)",
                severity=Severity.HIGH,
                description=(
                    f"WebSocket endpoint {ws_url} menerima upgrade request dari "
                    f"Origin arbitrary ({evil_origin}). Tanpa validasi Origin, "
                    f"penyerang bisa membuat halaman jahat yang membuka WebSocket "
                    f"ke server Anda menggunakan session/cookie korban (Cross-Site "
                    f"WebSocket Hijacking)."
                ),
                target=ws_url,
                urls=[ws_url],
                evidence=f"origin={evil_origin}, accepted_status={status}",
                cwe="CWE-346",
                confidence="confirmed",
                remediation=(
                    "1. Validasi Origin header pada WebSocket upgrade — reject jika bukan domain Anda.\n"
                    "2. Implementasi CSRF token sebagai parameter saat WebSocket connect.\n"
                    "3. Gunakan per-session ticket yang di-generate server-side.\n"
                    "4. Jangan rely hanya pada cookie untuk autentikasi WebSocket.\n"
                    "5. Log dan alert koneksi WebSocket dari Origin yang tidak dikenal."
                ),
                references=[
                    "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking",
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
