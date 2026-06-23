"""Regression test: scanner injeksi WAJIB menguji endpoint hasil crawler.

Bug historis (v0.10.6 ke bawah): sqli/xss/lfi/cmdi/ssti/redirect/csti hanya
menguji ``target.base_url`` dengan satu parameter sintetis sehingga endpoint
berparameter nyata (``/cari?q=``, ``/item?id=``, ``/view?file=``) tidak pernah
diuji. Test ini menanam celah nyata di endpoint yang HANYA bisa ditemukan
lewat crawling, lalu memastikan scanner menemukannya.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from cyberloka.active import lfi, sqli, xss
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.recon import crawler

HOME = (
    "<!doctype html><html><head><title>VulnLab</title></head><body>"
    '<a href="/search?q=test">search</a>'
    '<a href="/item?id=1">item</a>'
    '<a href="/view?file=index">view</a>'
    "</body></html>"
)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, body, ctype="text/html"):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = urlparse(self.path)
        q = parse_qs(p.query, keep_blank_values=True)
        if p.path == "/":
            return self._send(HOME)
        if p.path == "/search":
            return self._send(f"<html><body><h2>Hasil: {q.get('q', [''])[0]}</h2></body></html>")
        if p.path == "/item":
            val = q.get("id", [""])[0]
            if "'" in val or '"' in val:
                return self._send(
                    "<html><body>You have an error in your SQL syntax; check the "
                    "manual that corresponds to your MySQL server version</body></html>"
                )
            return self._send(f"<html><body>Item {val}</body></html>")
        if p.path == "/view":
            val = q.get("file", [""])[0]
            if "etc/passwd" in val.lower() or "etc%2fpasswd" in val.lower():
                return self._send(
                    "root:x:0:0:root:/root:/bin/bash\n", ctype="text/plain"
                )
            return self._send(f"<html><body>File: {val}</body></html>")
        self.send_response(404)
        self.end_headers()


@pytest.fixture(scope="module")
def vuln_server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{port}/"
    srv.shutdown()


def _setup(base_url):
    tgt = parse_target(base_url)
    cfg = ScanConfig(target=base_url, mode="active", max_crawl_pages=20, rate_limit=0)
    crawler.run(tgt, cfg)  # populate crawler state consumed by scanners
    return tgt, cfg


def test_crawler_discovers_param_endpoints(vuln_server):
    tgt, cfg = _setup(vuln_server)
    state = crawler.get_state(cfg)
    assert state is not None
    assert len(state.param_urls) >= 3


def test_sqli_finds_crawled_endpoint(vuln_server):
    tgt, cfg = _setup(vuln_server)
    findings = sqli.run(tgt, cfg)
    assert any("item" in f.target and f.confidence == "confirmed" for f in findings), (
        "SQLi harus menemukan celah error-based di /item?id= hasil crawl"
    )


def test_xss_finds_crawled_endpoint(vuln_server):
    tgt, cfg = _setup(vuln_server)
    findings = xss.run(tgt, cfg)
    assert any("search" in f.target for f in findings), (
        "XSS harus menemukan reflected XSS di /search?q= hasil crawl"
    )


def test_lfi_finds_crawled_endpoint(vuln_server):
    tgt, cfg = _setup(vuln_server)
    findings = lfi.run(tgt, cfg)
    assert any("view" in f.target and f.confidence == "confirmed" for f in findings), (
        "LFI harus menemukan path-traversal di /view?file= hasil crawl"
    )
