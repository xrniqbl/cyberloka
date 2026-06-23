"""Regresi auth_bypass admin-paths: HTTP 200 + substring "admin" TIDAK cukup.

Akar false-positive (simkopdes /administrator): server SPA membalas 200 berisi
beranda / halaman "404" yang dirender klien untuk path apa pun; beranda memuat
kata "admin"/"login" sehingga /administrator dilaporkan "firm" padahal saat
di-cek manual hasilnya 404. Modul kini wajib: tolak soft-404/echo beranda dan
butuh sinyal admin/login sungguhan (form password / software / title).

Mandiri — hanya stdlib http.server.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cyberloka.active import auth_bypass
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target

SPA_SHELL = (
    "<!DOCTYPE html><html lang=\"id\"><head><meta charset=\"utf-8\">"
    "<title>SIMKOPDES</title><script src=\"/_next/static/chunks/main.js\">"
    "</script></head><body><div id=\"__next\">"
    "<nav><a href=\"/login\">Admin Login</a></nav>"  # kata 'admin'/'login' ada di beranda
    "<h1>Selamat datang</h1></div></body></html>"
).encode()

SPA_404 = (
    "<!DOCTYPE html><html><head><title>SIMKOPDES</title></head><body>"
    "<div id=\"__next\"><h1>404 - Halaman tidak ditemukan</h1>"
    "<a href=\"/login\">Admin Login</a></div></body></html>"
).encode()

REAL_ADMIN_LOGIN = (
    "<!DOCTYPE html><html><head><title>Administrator Login</title></head><body>"
    "<form method=\"post\" action=\"/administrator\">"
    "<input name=\"user\" type=\"text\">"
    "<input name=\"pass\" type=\"password\">"
    "<button>Masuk</button></form></body></html>"
).encode()


def _make_handler(routes, default_spec=None, default_status=404):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            spec = routes.get(path)
            if spec is None and default_spec is not None:
                spec = default_spec
            if spec is None:
                self.send_response(default_status)
                self.end_headers()
                self.wfile.write(b"not found")
                return
            body, ctype = spec
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return H


def _serve(routes, default_spec=None, default_status=404) -> Iterator[str]:
    srv = HTTPServer(("127.0.0.1", 0), _make_handler(routes, default_spec, default_status))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        t.join(timeout=5)


def _admin_findings(base: str):
    cfg = ScanConfig(target=base, authorized=True, rate_limit=0.0)
    tgt = parse_target(base)
    # panggil langsung agar tidak tergantung crawler login-form
    from cyberloka.core import HttpClient
    from cyberloka.reporting.awam import get_awam
    client = HttpClient(cfg)
    try:
        return auth_bypass._probe_admin_paths(client, tgt, get_awam("auth_bypass"))
    finally:
        client.close()


# --- FP: SPA catch-all balas beranda (200) untuk SEMUA path -----------------
@pytest.fixture()
def spa_catchall_url() -> Iterator[str]:
    yield from _serve({}, default_spec=(SPA_SHELL, "text/html"))


def test_spa_catchall_no_admin_finding(spa_catchall_url):
    assert _admin_findings(spa_catchall_url) == [], (
        "Beranda SPA untuk /administrator TIDAK boleh dilaporkan"
    )


# --- FP: /administrator balas 200 berisi halaman "404" render klien ---------
@pytest.fixture()
def soft404_url() -> Iterator[str]:
    yield from _serve(
        {"/administrator": (SPA_404, "text/html"), "/": (SPA_SHELL, "text/html")},
        default_status=404,
    )


def test_soft_404_rejected(soft404_url):
    findings = _admin_findings(soft404_url)
    assert findings == [], "Response 200 berisi 'halaman tidak ditemukan' harus ditolak"


# --- True positive: /administrator login form sungguhan ---------------------
@pytest.fixture()
def real_admin_url() -> Iterator[str]:
    yield from _serve(
        {"/administrator": (REAL_ADMIN_LOGIN, "text/html"), "/": (SPA_SHELL, "text/html")},
        default_status=404,
    )


def test_real_admin_login_flagged_low(real_admin_url):
    findings = _admin_findings(real_admin_url)
    admin = [f for f in findings if f.target.endswith("/administrator")]
    assert len(admin) == 1
    # Form login = LOW informational, confidence firm
    assert admin[0].severity.value == "low"
    assert admin[0].confidence == "firm"
