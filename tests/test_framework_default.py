"""Regresi framework_default: catch-all 200 (mis. /.env & /_ignition pada
ods.kop.go.id yang balas 1569-byte HTML identik) TIDAK boleh jadi CRITICAL.

Mandiri — hanya stdlib http.server.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.recon import framework_default

# Halaman HTML catch-all (panjang tetap) yang dibalas untuk URL apa pun.
CATCHALL = (
    b"<!DOCTYPE html><html><head><title>ODS</title></head><body>"
    b"<div id=\"root\">Aplikasi tidak tersedia. key=value style text.</div>"
    b"</body></html>"
)


def _make_handler(routes, default_spec, methods=("GET", "POST")):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def _resp(self):
            path = self.path.split("?", 1)[0]
            spec = routes.get(path, default_spec)
            status, body, ctype = spec
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            self._resp()

        def do_POST(self):  # noqa: N802
            ln = int(self.headers.get("Content-Length") or 0)
            if ln:
                self.rfile.read(ln)
            self._resp()

    return H


def _serve(routes, default_spec) -> Iterator[str]:
    srv = HTTPServer(("127.0.0.1", 0), _make_handler(routes, default_spec))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        t.join(timeout=5)


def _run(base):
    return framework_default.run(parse_target(base), ScanConfig(target=base, authorized=True, rate_limit=0.0))


# --- FP: semua path (termasuk /.env & /_ignition) balas HTML catch-all ------
@pytest.fixture()
def catchall_url() -> Iterator[str]:
    yield from _serve({}, default_spec=(200, CATCHALL, "text/html"))


def test_catchall_no_findings(catchall_url):
    findings = _run(catchall_url)
    crit = [f for f in findings if f.severity.value == "critical"]
    assert crit == [], f"Catch-all 200 tak boleh jadi CRITICAL: {[f.title for f in crit]}"
    assert findings == [], "Tidak ada temuan dari halaman catch-all generik"


# --- TP: Laravel Ignition asli membalas error khas saat POST solution invalid
@pytest.fixture()
def ignition_url() -> Iterator[str]:
    err = b'{"message":"Class \\"Cyberloka\\\\Nonexistent\\\\Solution\\" does not exist","exception":"Facade\\\\Ignition"}'
    yield from _serve(
        {"/_ignition/execute-solution": (500, err, "application/json")},
        default_spec=(404, b"not found", "text/plain"),
    )


def test_real_ignition_flagged(ignition_url):
    findings = _run(ignition_url)
    ign = [f for f in findings if "Ignition" in f.title]
    assert len(ign) == 1 and ign[0].severity.value == "critical"
    assert ign[0].confidence == "firm"


# --- TP: .env asli berisi KEY=VALUE -----------------------------------------
@pytest.fixture()
def env_url() -> Iterator[str]:
    env = b"APP_KEY=base64:abc\nDB_PASSWORD=secret\nDB_HOST=127.0.0.1\n"
    yield from _serve(
        {"/.env": (200, env, "text/plain")},
        default_spec=(404, b"nf", "text/plain"),
    )


def test_real_env_flagged(env_url):
    findings = _run(env_url)
    envf = [f for f in findings if f.target.endswith("/.env")]
    assert len(envf) == 1 and envf[0].confidence == "confirmed"
