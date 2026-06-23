"""WebSocket origin / auth posture check.

We do an HTTP Upgrade handshake (no real WebSocket lib needed) with a forged
`Origin` header and check whether the server accepts the connection.
"""
from __future__ import annotations

import base64
import os
import re
from urllib.parse import urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

WS_HINT = re.compile(r"new\s+WebSocket\s*\(\s*['\"]([^'\"]+)['\"]")


def _candidate_ws(target: Target, config: ScanConfig) -> list[str]:
    out: list[str] = []
    state = get_state(config)
    if state:
        for u in state.urls[:10]:
            client = HttpClient(config)
            try:
                r = client.get(u)
            finally:
                client.close()
            if r is None:
                continue
            for m in WS_HINT.finditer(r.text or ""):
                out.append(m.group(1))
            if len(out) >= 3:
                break
    if not out:
        for path in ("/ws", "/socket", "/socket.io/?EIO=4&transport=websocket"):
            scheme = "wss" if target.scheme == "https" else "ws"
            out.append(f"{scheme}://{target.host}:{target.port}{path}")
    return out[:3]


def _ws_handshake(url: str, origin: str, config: ScanConfig) -> tuple[int, dict] | None:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("ws", "wss"):
        return None
    http_scheme = "https" if scheme == "wss" else "http"
    http_url = f"{http_scheme}://{parsed.netloc}{parsed.path or '/'}"
    if parsed.query:
        http_url += "?" + parsed.query
    key = base64.b64encode(os.urandom(16)).decode()
    headers = {
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": key,
        "Sec-WebSocket-Version": "13",
        "Origin": origin,
    }
    client = HttpClient(config)
    try:
        r = client.get(http_url, headers=headers, allow_redirects=False)
        if r is None:
            return None
        return r.status_code, dict(r.headers)
    finally:
        client.close()


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    candidates = _candidate_ws(target, config)
    if not candidates:
        return findings
    legit = f"{target.scheme}://{target.host}"
    evil = "https://cyberloka-evil.invalid"
    for url in candidates:
        try:
            r_legit = _ws_handshake(url, legit, config)
            r_evil = _ws_handshake(url, evil, config)
        except Exception:  # noqa: BLE001
            continue
        if r_legit is None or r_evil is None:
            continue
        if r_legit[0] == 101 and r_evil[0] == 101:
            findings.append(Finding(
                module="ws_check",
                title=f"WebSocket menerima Origin tidak terpercaya: {url}",
                severity=Severity.MEDIUM,
                description=("Endpoint WebSocket menerima upgrade dari domain attacker. "
                             "Jika tidak ada validasi auth/Origin server-side, attacker "
                             "dapat membuat halaman yang membuka koneksi atas nama korban "
                             "(Cross-Site WebSocket Hijacking)."),
                target=url,
                evidence=f"legit Origin -> {r_legit[0]}; evil Origin -> {r_evil[0]}",
                cwe="CWE-1385",
                remediation=("Validasi `Origin` di server WebSocket terhadap whitelist domain. "
                             "Wajibkan token autentikasi di handshake (cookie + CSRF token "
                             "atau ticket per-session)."),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html"
                ],
            ))
            return findings
    return findings
