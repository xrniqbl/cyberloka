"""Light HTTP request smuggling probe (CL.TE / TE.CL hint).

Only sends informational probes that should never trigger smuggling on a
correctly-configured server. We look for *abnormal* responses (timeout, 400,
or differing behavior) rather than confirming exploitation.
"""
from __future__ import annotations

import socket
import ssl

from cyberloka.core import Finding, Severity, Target
from cyberloka.core.config import ScanConfig

CL_TE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "User-Agent: Cyberloka-Probe\r\n"
    "Connection: close\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "X"
)
TE_CL = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "User-Agent: Cyberloka-Probe\r\n"
    "Connection: close\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "G"
)


def _send_raw(host: str, port: int, payload: str, use_tls: bool, timeout: float = 6.0) -> str:
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(payload.encode("ascii"))
        chunks = []
        sock.settimeout(timeout)
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) > 16384:
                break
        return b"".join(chunks).decode("latin-1", errors="replace")
    finally:
        try:
            sock.close()
        except OSError:
            pass


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if target.is_ip:
        return findings
    use_tls = target.scheme == "https"
    port = target.port
    host = target.host
    suspicions: list[str] = []
    try:
        for label, payload in (("CL.TE", CL_TE), ("TE.CL", TE_CL)):
            try:
                resp = _send_raw(host, port, payload.format(host=host), use_tls)
            except Exception as e:  # noqa: BLE001
                suspicions.append(f"{label} -> connection error: {e}")
                continue
            first_line = resp.split("\r\n", 1)[0] if resp else "(empty)"
            if resp.strip() == "":
                suspicions.append(f"{label}: timeout/empty response")
            elif "400" not in first_line and "200" in first_line:
                suspicions.append(f"{label}: server menerima request CL+TE -> {first_line}")
    except Exception:  # noqa: BLE001
        return findings

    if suspicions:
        findings.append(Finding(
            module="http_smuggling",
            title="Anomali respons pada probe Content-Length + Transfer-Encoding",
            severity=Severity.LOW,
            description=("Probe HTTP smuggling memunculkan respons tidak standar. Tidak "
                         "berarti exploit, tapi pantas dikonfirmasi manual: kombinasi "
                         "Content-Length + Transfer-Encoding harus selalu ditolak (400)."),
            target=f"{target.scheme}://{host}:{port}",
            evidence="\n".join(suspicions),
            cwe="CWE-444", confidence="tentative",
            remediation=("Pastikan front-end dan back-end memparse Content-Length dan "
                         "Transfer-Encoding secara konsisten; banyak proxy modern menolak "
                         "kombinasi keduanya. Update reverse proxy ke versi terbaru."),
            references=[
                "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn"
            ],
        ))
    return findings
