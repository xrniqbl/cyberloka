"""Regresi recon/ports: layanan harus TERKONFIRMASI (banner/handshake),
bukan sekadar diprediksi dari nomor port.

Mandiri — raw socket server stdlib.
"""
from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest

from cyberloka.recon import ports


def _serve_raw(handler) -> Iterator[tuple[str, int]]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def loop():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    try:
        yield ("127.0.0.1", port)
    finally:
        stop.set()
        srv.close()
        t.join(timeout=3)


# ---------------------------------------------------------------------------
# _plaintext_confirmed (unit)
# ---------------------------------------------------------------------------
def test_plaintext_confirmed_ftp_banner():
    assert ports._plaintext_confirmed(21, "220 ProFTPD 1.3.5") is True


def test_plaintext_unconfirmed_without_banner():
    assert ports._plaintext_confirmed(21, "") is False
    # port tanpa signature (rexec) tak bisa dikonfirmasi → False
    assert ports._plaintext_confirmed(512, "whatever") is False


# ---------------------------------------------------------------------------
# _probe_rdp — wajib handshake X.224 (TPKT), bukan port terbuka saja
# ---------------------------------------------------------------------------
@pytest.fixture()
def rdp_real():
    def handler(conn):
        try:
            conn.recv(64)
            conn.sendall(b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00")  # TPKT CC
        finally:
            conn.close()
    yield from _serve_raw(handler)


@pytest.fixture()
def rdp_fake():
    def handler(conn):
        try:
            conn.recv(64)
            conn.sendall(b"HELLO not rdp")  # bukan TPKT
        finally:
            conn.close()
    yield from _serve_raw(handler)


def test_rdp_confirmed_only_on_tpkt(rdp_real):
    host, port = rdp_real
    banner, finding = ports._probe_rdp(host, port)
    assert finding is not None and finding.confidence == "confirmed"
    assert finding.severity.value == "high"


def test_rdp_not_flagged_without_handshake(rdp_fake):
    host, port = rdp_fake
    banner, finding = ports._probe_rdp(host, port)
    assert finding is None, "Port 3389 tanpa handshake RDP tidak boleh dilaporkan"


# ---------------------------------------------------------------------------
# _probe_smtp_relay — wajib MAIL FROM 250 DAN RCPT TO 250
# ---------------------------------------------------------------------------
@pytest.fixture()
def smtp_open_relay():
    def handler(conn):
        try:
            conn.sendall(b"220 mail.test ESMTP\r\n")
            while True:
                data = conn.recv(256)
                if not data:
                    break
                u = data.upper()
                if u.startswith(b"EHLO"):
                    conn.sendall(b"250-mail.test\r\n250 OK\r\n")
                elif u.startswith(b"MAIL") or u.startswith(b"RCPT"):
                    conn.sendall(b"250 OK\r\n")
                elif u.startswith(b"QUIT"):
                    conn.sendall(b"221 Bye\r\n")
                    break
                else:
                    conn.sendall(b"250 OK\r\n")
        finally:
            conn.close()
    yield from _serve_raw(handler)


@pytest.fixture()
def smtp_secure():
    def handler(conn):
        try:
            conn.sendall(b"220 mail.test ESMTP\r\n")
            while True:
                data = conn.recv(256)
                if not data:
                    break
                u = data.upper()
                if u.startswith(b"EHLO"):
                    conn.sendall(b"250 mail.test\r\n")
                elif u.startswith(b"RCPT"):
                    conn.sendall(b"554 5.7.1 Relay denied\r\n")
                elif u.startswith(b"MAIL"):
                    conn.sendall(b"250 OK\r\n")
                elif u.startswith(b"QUIT"):
                    conn.sendall(b"221 Bye\r\n")
                    break
                else:
                    conn.sendall(b"250 OK\r\n")
        finally:
            conn.close()
    yield from _serve_raw(handler)


def test_smtp_open_relay_flagged(smtp_open_relay):
    host, port = smtp_open_relay
    _banner, finding = ports._probe_smtp_relay(host, port)
    assert finding is not None and finding.confidence == "firm"


def test_smtp_secure_not_flagged(smtp_secure):
    host, port = smtp_secure
    _banner, finding = ports._probe_smtp_relay(host, port)
    assert finding is None, "RCPT ditolak (554) tidak boleh dianggap open-relay"
