"""Regresi lintas-modul untuk pola false-positive soft-404 / SPA catch-all.

Memastikan modul probe-path TIDAK melaporkan temuan saat server SPA membalas
beranda/halaman-404 yang sama untuk URL apa pun, namun TETAP mendeteksi
layanan/akses nyata.

Mandiri — hanya stdlib http.server.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cyberloka.active import bypass_403, jenkins_unauth_console, phpmyadmin_exposed
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target

SPA_SHELL = (
    "<!DOCTYPE html><html><head><title>SIMKOPDES</title>"
    "<script src=\"/_next/static/main.js\"></script></head><body>"
    "<div id=\"__next\"><h1>Selamat datang</h1>"
    "<a href=\"/phpmyadmin/\">phpmyadmin</a></div></body></html>"
).encode()


def _make_handler(routes, default_spec=None, default_status=404):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def _send(self, status, body=b"", ctype="text/html", headers=None):
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            if body:
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            spec = routes.get(path)
            if spec is None and default_spec is not None:
                spec = default_spec
            if spec is None:
                self._send(default_status, b"not found")
                return
            self._send(spec.get("status", 200), spec.get("body", b""),
                       spec.get("ctype", "text/html"), spec.get("headers"))

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


def _cfg(base):
    return ScanConfig(target=base, authorized=True, rate_limit=0.0)


# ---------------------------------------------------------------------------
# phpmyadmin_exposed
# ---------------------------------------------------------------------------
@pytest.fixture()
def spa_catchall() -> Iterator[str]:
    # Beranda SPA (memuat substring 'phpmyadmin') dibalas untuk SEMUA path.
    yield from _serve({}, default_spec={"status": 200, "body": SPA_SHELL})


def test_phpmyadmin_spa_catchall_not_flagged(spa_catchall):
    findings = phpmyadmin_exposed.run(parse_target(spa_catchall), _cfg(spa_catchall))
    assert findings == [], "Beranda SPA berisi kata 'phpmyadmin' tak boleh dilaporkan"


@pytest.fixture()
def real_pma() -> Iterator[str]:
    body = (
        b"<html><head><title>phpMyAdmin</title>"
        b"<link rel=stylesheet href=phpmyadmin.css></head><body>"
        b"<form><input name=pma_username><input name=pma_password type=password>"
        b"</form></body></html>"
    )
    yield from _serve(
        {"/phpmyadmin/": {"status": 200, "body": body}},
        default_status=404,
    )


def test_real_phpmyadmin_flagged(real_pma):
    findings = phpmyadmin_exposed.run(parse_target(real_pma), _cfg(real_pma))
    assert len(findings) == 1 and findings[0].confidence == "confirmed"


# ---------------------------------------------------------------------------
# jenkins_unauth_console
# ---------------------------------------------------------------------------
def test_jenkins_spa_catchall_not_flagged(spa_catchall):
    findings = jenkins_unauth_console.run(parse_target(spa_catchall), _cfg(spa_catchall))
    assert findings == [], "SPA catch-all tak boleh memicu temuan Jenkins"


@pytest.fixture()
def real_jenkins() -> Iterator[str]:
    body = b"<html><body><h1>Script Console</h1><textarea name=scriptText></textarea>Groovy script</body></html>"
    yield from _serve({"/script": {"status": 200, "body": body}}, default_status=404)


def test_real_jenkins_script_flagged(real_jenkins):
    findings = jenkins_unauth_console.run(parse_target(real_jenkins), _cfg(real_jenkins))
    assert len(findings) == 1 and findings[0].severity.value == "critical"


# ---------------------------------------------------------------------------
# bypass_403
# ---------------------------------------------------------------------------
@pytest.fixture()
def bypass_spa() -> Iterator[str]:
    # /admin -> 403; tetapi server SPA membalas beranda 200 untuk path/header
    # mutasi apa pun (catch-all). Itu BUKAN bypass nyata.
    def handler_routes():
        return {}
    yield from _serve(
        {"/admin": {"status": 403, "body": b"Forbidden"}},
        default_spec={"status": 200, "body": SPA_SHELL},
    )


def test_bypass_403_spa_catchall_not_flagged(bypass_spa):
    findings = bypass_403.run(parse_target(bypass_spa), _cfg(bypass_spa))
    # /admin mutasi (/admin/, /admin/;/ dst) akan kena catch-all SPA 200 →
    # harus DITOLAK sebagai bypass palsu.
    assert findings == [], "Catch-all SPA 200 tidak boleh dianggap 403-bypass"
