"""Regresi: CORS reflect tanpa credentials = MEDIUM (bukan HIGH), dan
re-verifier (curl_active_verify) menolak signature yang muncul di catch-all.

Mandiri — stdlib http.server.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cyberloka.active import curl_active_verify
from cyberloka.core import Finding, Severity
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.passive import cors_advanced

CATCHALL = b"<!DOCTYPE html><html><body><script>var x={a:1};</script>catch-all { }</body></html>"


def _make_handler(routes, default_spec, reflect_origin=False, with_creds=False):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def _send(self, status, body, ctype, extra=None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            extra = {}
            if reflect_origin:
                origin = self.headers.get("Origin")
                if origin:
                    extra["Access-Control-Allow-Origin"] = origin
                    if with_creds:
                        extra["Access-Control-Allow-Credentials"] = "true"
            spec = routes.get(path, default_spec)
            status, body, ctype = spec
            self._send(status, body, ctype, extra)

    return H


def _serve(routes, default_spec, **kw) -> Iterator[str]:
    srv = HTTPServer(("127.0.0.1", 0), _make_handler(routes, default_spec, **kw))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        t.join(timeout=5)


def _cfg(base):
    return ScanConfig(target=base, authorized=True, rate_limit=0.0)


# --- CORS reflect tanpa credentials => MEDIUM -------------------------------
@pytest.fixture()
def cors_no_creds() -> Iterator[str]:
    yield from _serve({}, (200, b"{}", "application/json"), reflect_origin=True, with_creds=False)


@pytest.fixture()
def cors_with_creds() -> Iterator[str]:
    yield from _serve({}, (200, b"{}", "application/json"), reflect_origin=True, with_creds=True)


def test_cors_reflect_without_creds_is_medium(cors_no_creds):
    findings = cors_advanced.run(parse_target(cors_no_creds), _cfg(cors_no_creds))
    refl = [f for f in findings if "memantulkan Origin" in f.title]
    assert refl and refl[0].severity.value == "medium"


def test_cors_reflect_with_creds_is_high(cors_with_creds):
    findings = cors_advanced.run(parse_target(cors_with_creds), _cfg(cors_with_creds))
    refl = [f for f in findings if "memantulkan Origin" in f.title]
    assert refl and refl[0].severity.value == "high"


# --- Re-verifier menolak signature yang muncul di catch-all -----------------
@pytest.fixture()
def firebase_catchall() -> Iterator[str]:
    # /.json (recipe firebase, signature "{") balas HTML catch-all yang memuat "{".
    yield from _serve({}, (200, CATCHALL, "text/html"))


def test_reverifier_rejects_catchall_signature(firebase_catchall):
    base = firebase_catchall
    f = Finding(module="firebase_open_db", title="x", severity=Severity.HIGH,
                description="", target=base + "/.json", urls=[base + "/.json"])
    out = curl_active_verify.post_process([f], parse_target(base), _cfg(base))
    assert out[0].extra["curl_verified"] is False, (
        "Signature '{' yang muncul di halaman catch-all tidak boleh dianggap verified"
    )


# --- Re-verifier TETAP verify signature asli yang berbeda dari kontrol ------
@pytest.fixture()
def es_real() -> Iterator[str]:
    body = b'{"cluster_name":"prod-es","status":"green","number_of_nodes":3}'
    yield from _serve({"/_cluster/health": (200, body, "application/json")},
                      (404, b"nf", "text/plain"))


def test_reverifier_confirms_real_signature(es_real):
    base = es_real
    f = Finding(module="elasticsearch_unauth", title="x", severity=Severity.CRITICAL,
                description="", target=base + "/", urls=[base + "/"])
    out = curl_active_verify.post_process([f], parse_target(base), _cfg(base))
    assert out[0].extra["curl_verified"] is True
