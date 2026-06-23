"""Matriks test XSLT injection: server AMAN/reflektif (0 temuan) vs XSLT engine asli.

Membuktikan modul `xslt_injection` hanya melapor saat stylesheet benar-benar
DIEVALUASI processor — bukan saat input sekadar dipantulkan (refleksi).

Server "rentan" adalah XSLT engine-double: ia MENGEVALUASI ekspresi `<xsl:value-of
select="A*B"/>` dan mengembalikan HASIL perkaliannya (persis output processor XSLT
asli untuk stylesheet probe), tanpa dependensi eksternal. Server "aman" hanya
memantulkan body XML mentah — kasus yang dulu memicu false positive.
"""
from __future__ import annotations

import re
import threading
from collections.abc import Iterator

import pytest
from flask import Flask, Response, request
from werkzeug.serving import make_server

from cyberloka.active import xslt_injection
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.recon.crawler import CrawlState, _set_state

# Pola "value-of select" pada stylesheet probe — engine-double mengevaluasinya.
_VALUE_OF = re.compile(r'<xsl:value-of\s+select="(\d+)\*(\d+)"\s*/>')
_TEXT = re.compile(r'<xsl:template[^>]*>(.*?)</xsl:template>', re.S)


def _serve(app: Flask) -> Iterator[str]:
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        t.join(timeout=5)


# ---- Server AMAN: hanya MEMANTULKAN body XML (tidak ada engine XSLT) ----
def _reflect_app() -> Flask:
    app = Flask(__name__)

    @app.route("/transform", methods=["GET", "POST"])
    def transform() -> Response:
        body = request.get_data(as_text=True)
        # Echo input mentah ke pesan error — pola umum yang dulu memicu FP.
        return Response(f"<error>cannot parse stylesheet: {body}</error>",
                        content_type="application/xml")

    return app


# ---- Server RENTAN: mengEVALUASI stylesheet (engine-double, output = hasil) ----
def _vuln_app() -> Flask:
    app = Flask(__name__)

    @app.route("/transform", methods=["GET", "POST"])
    def transform() -> Response:
        body = request.get_data(as_text=True) or ""
        m = _TEXT.search(body)
        if not m:
            return Response("no template", content_type="text/plain", status=400)
        # Evaluasi: ganti <xsl:value-of select="A*B"/> dengan HASIL A*B.
        out = _VALUE_OF.sub(lambda g: str(int(g.group(1)) * int(g.group(2))), m.group(1))
        return Response(out, content_type="text/plain")

    return app


def _prime_state(config: ScanConfig, base_url: str) -> None:
    """Suntik crawl state agar modul punya kandidat URL '/transform'."""
    st = CrawlState(urls=[f"{base_url}/transform"])
    _set_state(config, st)


@pytest.fixture()
def reflect_url() -> Iterator[str]:
    yield from _serve(_reflect_app())


@pytest.fixture()
def vuln_url() -> Iterator[str]:
    yield from _serve(_vuln_app())


def test_reflective_server_is_not_flagged(reflect_url):
    """Server yang sekadar memantulkan stylesheet TIDAK boleh dilaporkan."""
    cfg = ScanConfig(target=reflect_url, authorized=True, rate_limit=0.0)
    _prime_state(cfg, reflect_url)
    findings = xslt_injection.run(parse_target(reflect_url), cfg)
    assert findings == [], "echo/refleksi bukan eksekusi XSLT — tidak boleh jadi temuan"


def test_real_xslt_engine_is_detected(vuln_url):
    """Server yang BENAR-BENAR mengeksekusi stylesheet HARUS terdeteksi confirmed."""
    cfg = ScanConfig(target=vuln_url, authorized=True, rate_limit=0.0)
    _prime_state(cfg, vuln_url)
    findings = xslt_injection.run(parse_target(vuln_url), cfg)
    assert len(findings) == 1, "XSLT engine asli harus terdeteksi"
    assert findings[0].confidence == "confirmed"
    assert findings[0].module == "xslt_injection"
    assert findings[0].severity.value == "critical"
