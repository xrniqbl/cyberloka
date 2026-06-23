"""Regresi spring_actuator_rce: heapdump butuh bukti biner ter-anchor, bukan
sekadar 2 byte magic gzip di tengah teks (yang dulu memicu CRITICAL palsu).

Mandiri — hanya butuh stdlib http.server.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cyberloka.active import spring_actuator_rce
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target


def _make_handler(routes: dict):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):  # noqa: N802
            spec = routes.get(self.path)
            if spec is None:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
                return
            body, ctype = spec
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def _serve(routes: dict) -> Iterator[str]:
    srv = HTTPServer(("127.0.0.1", 0), _make_handler(routes))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        t.join(timeout=5)


def _run(base: str):
    cfg = ScanConfig(target=base, authorized=True, rate_limit=0.0)
    return spring_actuator_rce.run(parse_target(base), cfg)


# --- FP: halaman 200 yang kebetulan memuat byte 0x1f 0x8b di TENGAH teks ---
@pytest.fixture()
def decoy_url() -> Iterator[str]:
    decoy = ("<html><body>laporan\x1f\x8bdiagnostik</body></html>").encode("latin-1")
    yield from _serve({
        "/actuator/heapdump": (decoy, "text/html"),
        "/heapdump": (decoy, "text/html"),
    })


def test_gzip_byte_in_text_is_not_flagged(decoy_url):
    assert _run(decoy_url) == [], "byte gzip di tengah HTML bukan heapdump — tak boleh CRITICAL"


# --- Real: HPROF tak-terkompresi (signature teks di awal) ---
@pytest.fixture()
def hprof_url() -> Iterator[str]:
    body = b"JAVA PROFILE 1.0.2\x00" + b"\x00" * 2048
    yield from _serve({"/actuator/heapdump": (body, "application/octet-stream")})


def test_real_hprof_is_detected(hprof_url):
    f = _run(hprof_url)
    assert len(f) == 1 and f[0].confidence == "confirmed"
    assert f[0].severity.value == "critical"


# --- Real: heapdump terkompresi gzip (magic di AWAL + ct biner + besar) ---
@pytest.fixture()
def gzip_dump_url() -> Iterator[str]:
    body = b"\x1f\x8b\x08\x00" + b"\x00" * 4096
    yield from _serve({"/actuator/heapdump": (body, "application/octet-stream")})


def test_real_gzip_heapdump_is_detected(gzip_dump_url):
    f = _run(gzip_dump_url)
    assert len(f) == 1 and f[0].confidence == "confirmed"


# --- Kontrol positif lain: /actuator/env JSON tetap terdeteksi ---
@pytest.fixture()
def env_url() -> Iterator[str]:
    body = b'{"propertySources":[{"name":"systemEnvironment"}]}'
    yield from _serve({"/actuator/env": (body, "application/json")})


def test_env_still_detected(env_url):
    f = _run(env_url)
    assert len(f) == 1 and f[0].confidence == "confirmed"
