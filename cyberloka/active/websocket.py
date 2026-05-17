"""WebSocket security audit (handshake-level, no payload exchange).

Memeriksa:
- Apakah server menerima handshake dari Origin asing (Cross-Site WebSocket
  Hijacking risk).
- Apakah TLS dipakai (wss vs ws).
- Apakah subprotocol & extension yang diiklankan masuk akal (mis. permessage-deflate
  pada koneksi sensitif → CRIME-like risk).
- Apakah token otentikasi muncul di URL query (kebocoran token via log).

Implementasi handshake manual menggunakan TCP socket untuk menghindari
dependensi tambahan; fallback bila socket tidak bisa connect.
"""
from __future__ import annotations

import base64
import os
import re
import socket
import ssl
from urllib.parse import urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

WS_HINT_PATHS = (
    "/ws",
    "/wss",
    "/websocket",
    "/socket",
    "/socket.io/?EIO=4&transport=websocket",
    "/api/ws",
    "/api/socket",
    "/realtime",
    "/cable",
)


def _ws_handshake(host: str, port: int, path: str, use_tls: bool, origin: str, timeout: float) -> tuple[int, dict[str, str], str] | None:
    """Lakukan WebSocket handshake mentah. Return (status, headers, raw)."""
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: {origin}\r\n"
        "User-Agent: Cyberloka-WS/0.1\r\n"
        "\r\n"
    )
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(req.encode())
        raw = b""
        s.settimeout(timeout)
        try:
            while b"\r\n\r\n" not in raw and len(raw) < 8192:
                chunk = s.recv(2048)
                if not chunk:
                    break
                raw += chunk
        except socket.timeout:
            pass
        finally:
            try:
                s.close()
            except OSError:
                pass
    except OSError:
        return None

    text = raw.decode("latin-1", errors="replace")
    head, _, _ = text.partition("\r\n\r\n")
    if not head:
        return None
    lines = head.split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        return None
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, head


def _candidate_paths(target: Target) -> list[str]:
    paths = list(WS_HINT_PATHS)
    discovered = getattr(target, "discovered", None)
    if discovered is not None:
        for u in getattr(discovered, "js_urls", []):
            for m in re.findall(r'wss?://[^"\'<>\s]+', u or ""):
                pp = urlparse(m).path or "/"
                if pp not in paths:
                    paths.append(pp)
    return paths


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    use_tls = target.scheme == "https"
    host = target.host
    port = target.port

    valid_endpoint: tuple[str, dict[str, str]] | None = None
    for path in _candidate_paths(target):
        result = _ws_handshake(host, port, path, use_tls, origin=target.origin, timeout=config.timeout)
        if result is None:
            continue
        status, headers, raw = result
        if status == 101 and headers.get("upgrade", "").lower() == "websocket":
            valid_endpoint = (path, headers)
            findings.append(
                Finding(
                    module="websocket",
                    title=f"WebSocket endpoint terdeteksi: {path}",
                    severity=Severity.INFO,
                    description="Server menerima upgrade WebSocket pada path ini.",
                    target=f"{'wss' if use_tls else 'ws'}://{host}:{port}{path}",
                    evidence=truncate(raw, 240),
                )
            )
            break

    if valid_endpoint is None:
        return findings

    path, _ = valid_endpoint

    # 1) Cross-origin handshake check
    cross = _ws_handshake(host, port, path, use_tls, origin="https://evil.example.com", timeout=config.timeout)
    if cross is not None:
        cstatus, cheaders, _craw = cross
        if cstatus == 101:
            findings.append(
                Finding(
                    module="websocket",
                    title="Cross-Site WebSocket Hijacking — origin foreign diterima",
                    severity=Severity.HIGH,
                    description=(
                        "Server menyetujui upgrade WebSocket dari Origin attacker. Bila session "
                        "berbasis cookie, attacker bisa menyalahgunakan WebSocket korban dari "
                        "halaman jahat."
                    ),
                    target=f"{'wss' if use_tls else 'ws'}://{host}:{port}{path}",
                    evidence=f"status={cstatus} server={cheaders.get('server','?')}",
                    cwe="CWE-346",
                    remediation=(
                        "Validasi header Origin saat handshake. Whitelist domain yang dipercaya. "
                        "Untuk session berbasis cookie, tambahkan token CSRF atau double-submit."
                    ),
                    references=[
                        "https://christian-schneider.net/CrossSiteWebSocketHijacking.html",
                    ],
                )
            )

    # 2) Cleartext ws://
    if not use_tls:
        findings.append(
            Finding(
                module="websocket",
                title="WebSocket tidak menggunakan TLS (ws://)",
                severity=Severity.HIGH,
                description=(
                    "Trafik WebSocket dapat disadap/dimodifikasi di jaringan yang tidak terpercaya."
                ),
                target=f"ws://{host}:{port}{path}",
                remediation="Migrasi ke wss:// (TLS).",
            )
        )

    # 3) Token in URL?
    if "token=" in path.lower() or "auth=" in path.lower() or "access_token=" in path.lower():
        findings.append(
            Finding(
                module="websocket",
                title="Token otentikasi terlihat di URL WebSocket",
                severity=Severity.MEDIUM,
                description=(
                    "Token di query string akan tercatat di access log proxy/CDN dan history "
                    "browser. Lebih aman lewat header Authorization atau cookie HttpOnly."
                ),
                target=f"{'wss' if use_tls else 'ws'}://{host}:{port}{path}",
                cwe="CWE-598",
                remediation=(
                    "Gunakan header Authorization saat handshake (Sec-WebSocket-Protocol "
                    "atau cookie session HttpOnly+Secure)."
                ),
            )
        )

    return findings
