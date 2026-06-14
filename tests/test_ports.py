"""Tests for the --ports spec parser and custom-range scanning."""
from __future__ import annotations

import socket
import threading

from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.recon.ports import parse_ports, run


def test_parse_ports_specs():
    assert parse_ports("all") == list(range(1, 65536))
    assert parse_ports("full") == list(range(1, 65536))
    assert parse_ports("1-65535") == list(range(1, 65536))
    assert parse_ports("22,80,443") == [22, 80, 443]
    assert parse_ports("8000-8002") == [8000, 8001, 8002]
    assert parse_ports("80,8000-8002,22") == [22, 80, 8000, 8001, 8002]
    assert parse_ports("100-90") == list(range(90, 101))  # reversed range
    assert parse_ports("0,70000,abc,443") == [443]  # clamp + junk ignored
    assert parse_ports(None) == []
    assert parse_ports("") == []


def _open_listener() -> tuple[socket.socket, int]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def loop():
        while True:
            try:
                c, _ = srv.accept()
                c.close()
            except OSError:
                break

    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1]


def test_custom_port_scan_finds_uncommon_port():
    srv, port = _open_listener()
    try:
        cfg = ScanConfig(target="http://127.0.0.1/", ports=str(port),
                         timeout=2.0, threads=10)
        findings = run(parse_target("http://127.0.0.1/"), cfg)
    finally:
        srv.close()
    summary = [f for f in findings if "port terbuka" in f.title]
    assert summary, "open-port finding expected"
    assert str(port) in summary[0].evidence


def test_default_scan_skips_uncommon_port():
    srv, port = _open_listener()
    try:
        cfg = ScanConfig(target="http://127.0.0.1/", timeout=2.0, threads=10)
        findings = run(parse_target("http://127.0.0.1/"), cfg)
    finally:
        srv.close()
    assert not any(str(port) in (f.evidence or "") for f in findings)
