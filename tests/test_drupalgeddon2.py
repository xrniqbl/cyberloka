"""Matriks regresi Drupalgeddon2 (CVE-2018-7600) + re-verifikasi.

Membuktikan modul hanya melapor saat callable `printf` BENAR-BENAR dieksekusi
(transformasi `%%`->`%`), bukan saat markup sekadar dipantulkan mentah. Server
"rentan" mengemulasi perilaku printf; server "reflektif" mengembalikan markup apa
adanya; server "patched" tak memproses #post_render. Mandiri (stdlib http.server).
"""
from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from cyberloka.active import drupalgeddon2, curl_active_verify
from cyberloka.core import HttpClient
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target


def _markup_from_path(path: str) -> str:
    q = parse_qs(urlsplit(path).query)
    vals = q.get("name[#markup]", [])
    return vals[0] if vals else ""


def _make_handler(mode: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            markup = _markup_from_path(self.path)
            if mode == "vuln":
                # Emulasi printf: '%%' -> '%' (callable benar-benar dieksekusi).
                out = markup.replace("%%", "%")
                body = f"<html><body>{out}</body></html>"
            elif mode == "reflect":
                # Server hanya memantulkan markup mentah (tanpa eksekusi).
                body = f"<html><body>echo: {markup}</body></html>"
            else:  # patched: tidak memproses #post_render sama sekali
                body = "<html><body><form>reset password</form></body></html>"
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

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


@pytest.fixture()
def vuln_url() -> Iterator[str]:
    yield from _serve("vuln")


@pytest.fixture()
def reflect_url() -> Iterator[str]:
    yield from _serve("reflect")


@pytest.fixture()
def patched_url() -> Iterator[str]:
    yield from _serve("patched")


def _run(base: str):
    cfg = ScanConfig(target=base, authorized=True, rate_limit=0.0)
    return drupalgeddon2.run(parse_target(base), cfg)


# ---- modul ----
def test_oracle_is_reflection_proof():
    markup, executed, reflected = drupalgeddon2.make_oracle()
    # executed (satu %) BUKAN substring reflected (dua %) -> saling eksklusif
    assert executed not in reflected
    assert drupalgeddon2.is_executed(f"x {executed} y", executed, reflected)
    assert not drupalgeddon2.is_executed(f"x {reflected} y", executed, reflected)


def test_vulnerable_server_is_confirmed(vuln_url):
    f = _run(vuln_url)
    assert len(f) == 1
    assert f[0].confidence == "confirmed"
    assert f[0].severity.value == "critical"


def test_reflective_server_not_flagged(reflect_url):
    assert _run(reflect_url) == [], "refleksi markup mentah bukan eksekusi printf"


def test_patched_server_not_flagged(patched_url):
    assert _run(patched_url) == []


# ---- re-verifikasi (curl_active_verify) ----
def test_reverify_confirms_vulnerable(vuln_url):
    client = HttpClient(ScanConfig(target=vuln_url, authorized=True, rate_limit=0.0))
    try:
        res = curl_active_verify._verify_drupalgeddon2(client, parse_target(vuln_url))
    finally:
        client.close()
    assert res["verified"] is True and res["response_match"] is True


def test_reverify_rejects_reflective(reflect_url):
    client = HttpClient(ScanConfig(target=reflect_url, authorized=True, rate_limit=0.0))
    try:
        res = curl_active_verify._verify_drupalgeddon2(client, parse_target(reflect_url))
    finally:
        client.close()
    assert res["verified"] is False
    assert "RCE TIDAK terbukti" in res["note"]
