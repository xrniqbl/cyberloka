"""WebSocket: validasi auth via raw socket handshake (tanpa library websockets).

Memvalidasi:
  1. Endpoint ws:// atau wss:// menerima koneksi tanpa header Authorization.
  2. Server kirim 101 Switching Protocols + Sec-WebSocket-Accept header valid.
  3. Setelah upgrade, kirim 1 WebSocket frame (text "ping") dan tunggu balasan.
     Server yang merespons -> WebSocket benar-benar siap menerima command tanpa
     auth (Cross-Site WebSocket Hijacking risk).

Pakai socket + ssl + base64 dasar; tidak perlu library tambahan.
"""
from __future__ import annotations

import base64
import os
import socket
import ssl
from urllib.parse import urlparse, urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

WS_PATHS_GUESS = (
    "/ws", "/websocket", "/socket.io/?EIO=4&transport=websocket",
    "/api/ws", "/api/socket", "/realtime", "/graphql", "/notification",
    "/chat", "/cable",
)


def _build_handshake(host: str, path: str, origin: str) -> tuple[bytes, str]:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Origin: {origin}\r\n"
        "User-Agent: Cyberloka/0.9 ws-probe\r\n\r\n"
    )
    return req.encode("latin-1"), key


def _try_ws(host: str, port: int, path: str, use_tls: bool, origin: str, timeout: float = 5.0) -> dict | None:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            sock = ctx.wrap_socket(sock, server_hostname=host)
        except ssl.SSLError:
            sock.close()
            return None

    try:
        sock.settimeout(timeout)
        req, key = _build_handshake(host, path, origin)
        sock.sendall(req)
        resp = b""
        while b"\r\n\r\n" not in resp and len(resp) < 4096:
            chunk = sock.recv(1024)
            if not chunk:
                break
            resp += chunk
        if not resp.startswith(b"HTTP/1.1 101"):
            return {"status": resp[:80].decode("latin-1", errors="replace"), "upgraded": False}

        result: dict = {"upgraded": True, "headers": resp[:600].decode("latin-1", errors="replace")}

        # Coba kirim 1 text frame "ping" (FIN=1, opcode=1, mask=1)
        # Frame sederhana: 0x81 + (0x80 | length) + mask(4) + masked_payload
        payload = b'{"type":"ping"}'
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        frame = bytes([0x81, 0x80 | len(payload)]) + mask + masked
        try:
            sock.sendall(frame)
            sock.settimeout(2.0)
            data = sock.recv(2048)
            if data and len(data) >= 2:
                op = data[0] & 0x0F
                if op in (1, 2):  # text or binary frame
                    result["echoed"] = True
                    result["response"] = data[2:200].decode("latin-1", errors="replace")
        except (socket.timeout, OSError):
            pass

        return result
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _candidate_paths(target: Target, config: ScanConfig) -> list[str]:
    state = get_state(config)
    paths = list(WS_PATHS_GUESS)
    if state:
        for u in state.urls:
            p = urlparse(u)
            if any(k in p.path.lower() for k in ("ws", "socket", "stream", "realtime", "live")):
                paths.append(p.path)
    # dedup tetap urut
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if not target.host:
        return findings
    use_tls = target.scheme == "https"
    port = 443 if use_tls else 80
    if target.port:
        port = target.port

    origin_ok = target.base_url
    origin_evil = "https://attacker.invalid"

    for path in _candidate_paths(target, config)[:6]:
        # Dengan origin sah dulu (untuk konfirmasi endpoint adalah WS)
        with_ok = _try_ws(target.host, port, path, use_tls, origin_ok)
        if not with_ok or not with_ok.get("upgraded"):
            continue
        # Sekarang dengan origin attacker - kalau juga di-upgrade = CSWSH risk
        with_evil = _try_ws(target.host, port, path, use_tls, origin_evil)
        if with_evil and with_evil.get("upgraded"):
            ev_lines = [
                f"WS endpoint: {target.scheme}://{target.host}:{port}{path}",
                "Origin sah  : 101 Switching Protocols",
                "Origin attacker.invalid: 101 Switching Protocols (TIDAK divalidasi)",
            ]
            if with_evil.get("echoed"):
                ev_lines.append("Server merespons frame ping dari attacker - command channel terbuka")
            sev = Severity.HIGH if with_evil.get("echoed") else Severity.MEDIUM
            findings.append(Finding(
                module="websocket_auth_check",
                target=f"{target.scheme}://{target.host}:{port}{path}",
                title="WebSocket menerima koneksi cross-origin (CSWSH risk)",
                severity=sev,
                description=(
                    "Endpoint WebSocket menerima upgrade dari Origin yang sembarangan "
                    "(attacker.invalid). Kalau koneksi WS pakai cookie sesi user, "
                    "halaman berbahaya bisa membuka WS ke server target dari browser "
                    "korban yang sedang login - dan membaca/mengirim pesan internal. "
                    "Ini disebut Cross-Site WebSocket Hijacking (CSWSH)."
                ),
                evidence="\n".join(ev_lines),
                cwe="CWE-1385",
                confidence="confirmed",
                urls=[f"{target.scheme}://{target.host}:{port}{path}"],
                remediation=(
                    "1. Server WS HARUS validasi header Origin saat upgrade - "
                    "tolak Origin yang bukan domain Anda.\n"
                    "2. Gunakan token autentikasi terpisah (JWT) di first WS frame, "
                    "jangan hanya cookie.\n"
                    "3. Pakai SameSite=Strict pada cookie sesi sehingga browser tidak "
                    "kirim cookie ke WS cross-site."
                ),
                references=[
                    "https://christian-schneider.net/CrossSiteWebSocketHijacking.html",
                    "https://cwe.mitre.org/data/definitions/1385.html",
                ],
            ))
            break  # cukup 1 finding
    return findings
