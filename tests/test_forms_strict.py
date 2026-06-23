"""Regression test: form fuzzer harus terbukti (no false-positive).

- Form yang memantulkan input MENTAH -> XSS dilaporkan (confirmed).
- Form yang meng-escape input -> TIDAK dilaporkan (anti false-positive).
"""
from __future__ import annotations

import threading
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import pytest

from cyberloka.active import forms
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.recon import crawler

HOME = (
    "<!doctype html><html><body>"
    '<form method="post" action="/comment"><input name="text"><input type="submit"></form>'
    '<form method="post" action="/safe"><input name="name"><input type="submit"></form>'
    "</body></html>"
)


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype="text/html"):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/":
            return self._send(HOME)
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = parse_qs(self.rfile.read(n).decode(), keep_blank_values=True)
        if self.path == "/comment":  # VULNERABLE: raw reflection
            return self._send(f"<html><body>Komentar: {data.get('text', [''])[0]}</body></html>")
        if self.path == "/safe":     # SAFE: escaped reflection
            return self._send(f"<html><body>Halo: {escape(data.get('name', [''])[0])}</body></html>")
        self.send_response(404)
        self.end_headers()


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), _H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()


def _findings(base):
    tgt = parse_target(base)
    cfg = ScanConfig(target=base, mode="active", max_crawl_pages=10, rate_limit=0)
    crawler.run(tgt, cfg)
    return forms.run(tgt, cfg)


def test_form_xss_confirmed(server):
    fs = _findings(server)
    assert any("/comment" in f.target and f.confidence == "confirmed" for f in fs), (
        "Form reflektif mentah harus dilaporkan XSS confirmed"
    )


def test_safe_form_not_flagged(server):
    fs = _findings(server)
    assert not any("/safe" in f.target for f in fs), (
        "Form yang meng-escape input TIDAK boleh dilaporkan (false-positive)"
    )
