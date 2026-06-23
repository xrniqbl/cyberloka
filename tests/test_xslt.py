"""Matriks regresi XSLT injection: server reflektif (0 temuan) vs XSLT engine asli.

Mandiri — hanya butuh stdlib `http.server`. Bagian "engine asli" memakai lxml
(XSLT processor sungguhan) dan otomatis di-skip bila lxml tak terpasang.

Membuktikan modul `xslt_injection` hanya melapor saat stylesheet benar-benar
DIEVALUASI processor, bukan saat input sekadar dipantulkan (refleksi). Test ini
juga menjaga agar marker tetap PENJUMLAHAN (bukan perkalian) sehingga hasil tidak
pernah jatuh ke notasi ilmiah XSLT 1.0 yang akan memecah pencocokan.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cyberloka.active import xslt_injection
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.recon.crawler import CrawlState, _set_state


def _make_handler(mode: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):  # silence
            pass

        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n)
            if mode == "echo":
                out = b"<error>cannot parse stylesheet: " + body + b"</error>"
            else:  # real XSLT engine via lxml
                from lxml import etree
                try:
                    transformer = etree.XSLT(etree.fromstring(body))
                    out = str(transformer(etree.fromstring(b"<root/>"))).encode()
                except Exception:  # noqa: BLE001
                    out = b"err"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        do_GET = do_POST  # noqa: N815

    return Handler


def _serve(mode: str) -> Iterator[str]:
    srv = HTTPServer(("127.0.0.1", 0), _make_handler(mode))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        t.join(timeout=5)


def _run(base: str):
    cfg = ScanConfig(target=base, authorized=True, rate_limit=0.0)
    _set_state(cfg, CrawlState(urls=[f"{base}/transform"]))
    return xslt_injection.run(parse_target(base), cfg)


@pytest.fixture()
def echo_url() -> Iterator[str]:
    yield from _serve("echo")


@pytest.fixture()
def xslt_url() -> Iterator[str]:
    yield from _serve("xslt")


def test_reflective_server_is_not_flagged(echo_url):
    """Server yang sekadar memantulkan stylesheet TIDAK boleh dilaporkan."""
    assert _run(echo_url) == [], "echo/refleksi bukan eksekusi XSLT — tidak boleh jadi temuan"


def test_real_xslt_engine_is_detected(xslt_url):
    """Server yang BENAR-BENAR mengeksekusi stylesheet HARUS terdeteksi confirmed."""
    pytest.importorskip("lxml")
    findings = _run(xslt_url)
    assert len(findings) == 1, "XSLT engine asli harus terdeteksi"
    assert findings[0].confidence == "confirmed"
    assert findings[0].severity.value == "critical"
    assert findings[0].module == "xslt_injection"
