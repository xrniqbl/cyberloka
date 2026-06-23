"""Regresi websocket_auth_check: timeout saat handshake TIDAK boleh crash modul.

Dulu `sock.recv` di loop handshake tidak ditangani, sehingga server yang menerima
koneksi tapi tak membalas membuat TimeoutError menggagalkan seluruh scan.
Mandiri — hanya stdlib (socket/threading).
"""
from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest

from cyberloka.active import websocket_auth_check as ws
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target


def _raw_server(mode: str) -> tuple[socket.socket, int]:
    """TCP listener. mode='silent' menerima koneksi tapi tak membalas;
    mode='http400' membalas respons HTTP non-101 lalu menutup."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            if mode == "http400":
                try:
                    conn.recv(2048)
                    conn.sendall(b"HTTP/1.1 400 Bad Request\r\n"
                                 b"Content-Length: 0\r\n\r\n")
                except OSError:
                    pass
                conn.close()
            else:  # silent: simpan koneksi terbuka tanpa membalas
                # jangan close cepat — biar sisi klien kena timeout recv
                threading.Timer(2.0, lambda c=conn: c.close()).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv, port


@pytest.fixture()
def silent() -> Iterator[int]:
    srv, port = _raw_server("silent")
    try:
        yield port
    finally:
        srv.close()


@pytest.fixture()
def http400() -> Iterator[int]:
    srv, port = _raw_server("http400")
    try:
        yield port
    finally:
        srv.close()


def test_try_ws_timeout_returns_none_not_raise(silent):
    """Handshake yang time out harus mengembalikan None, bukan melempar TimeoutError."""
    result = ws._try_ws("127.0.0.1", silent, "/ws", use_tls=False,
                        origin="http://x", timeout=0.5)
    assert result is None


def test_try_ws_non_101_is_not_upgraded(http400):
    result = ws._try_ws("127.0.0.1", http400, "/ws", use_tls=False,
                        origin="http://x", timeout=2.0)
    assert result is not None and result.get("upgraded") is False


def test_run_does_not_crash_on_non_ws_server(http400):
    cfg = ScanConfig(target=f"http://127.0.0.1:{http400}", authorized=True, rate_limit=0.0)
    findings = ws.run(parse_target(f"http://127.0.0.1:{http400}"), cfg)
    assert findings == []
