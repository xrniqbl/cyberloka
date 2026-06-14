"""Regression tests for the confidence audit / false-positive fixes."""
from __future__ import annotations

import threading
from collections.abc import Iterator

import pytest
from flask import Flask, Response
from werkzeug.serving import make_server

from cyberloka.active import xxe
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target


def _safe_xxe_app() -> Flask:
    app = Flask(__name__)

    # A SECURE XML parser rejects the DTD. Cyberloka must NOT flag this.
    @app.route("/", methods=["GET", "POST"])
    @app.route("/<path:_p>", methods=["GET", "POST"])
    def any_route(_p: str = "") -> Response:
        return Response(
            "<error>DOCTYPE is not allowed</error>",
            content_type="application/xml", status=400)

    return app


@pytest.fixture()
def safe_xxe_url() -> Iterator[str]:
    srv = make_server("127.0.0.1", 0, _safe_xxe_app(), threaded=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        t.join(timeout=5)


def test_xxe_does_not_flag_protected_server(safe_xxe_url):
    # "DOCTYPE is not allowed" means the parser blocked the DTD => SAFE.
    cfg = ScanConfig(target=safe_xxe_url, authorized=True, rate_limit=0.0)
    findings = xxe.run(parse_target(safe_xxe_url), cfg)
    assert findings == [], "a server that rejects DTDs must not be reported as XXE"
