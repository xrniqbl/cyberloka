"""Tier-2 verification: ssrf / url_preview_ssrf must NOT fire when the app merely
echoes the URL (no real fetch), but MUST fire when the server actually fetches the
internal metadata endpoint.
"""
import threading

import pytest
from flask import Flask, Response, request
from werkzeug.serving import make_server

from cyberloka.core import Finding
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.scanner import run_scan

MODS = ["crawler", "ssrf", "url_preview_ssrf"]
META = "ami-id: ami-0123 instance-id: i-abc iam/security-credentials/role accesskeyid: AKIA"


def _echo_app() -> Flask:
    """FP trap: echoes the submitted URL back (with a <title>) — never fetches."""
    app = Flask(__name__)

    @app.route("/")
    def home():
        return Response("<html><body><a href='/fetch?url=http://example.com'>f</a></body></html>",
                        content_type="text/html")

    @app.route("/fetch")
    def fetch():
        u = request.args.get("url", "")
        return Response(f"<html><title>Preview of {u}</title><body>{u}</body></html>",
                        content_type="text/html")

    @app.route("/api/preview", methods=["GET", "POST"])
    def preview():
        u = (request.get_json(silent=True) or {}).get("url") if request.is_json else request.args.get("url", "")
        return Response(f"<html><title>Preview of {u}</title></html>", content_type="text/html")

    return app


def _fetcher_app() -> Flask:
    """Real SSRF: server actually fetches the URL and returns its content."""
    app = Flask(__name__)

    def _serve(u: str) -> Response:
        if "169.254.169.254" in u:
            return Response(f"<html><body>{META}</body></html>", content_type="text/html")
        if "metadata.google" in u:
            return Response("<html><body>computeMetadata metadata-flavor service-accounts/</body></html>",
                            content_type="text/html")
        if "invalid" in u:
            return Response("<html><body>error: could not resolve host</body></html>",
                            content_type="text/html")
        return Response(f"<html><title>Preview</title><body>fetched {u}</body></html>",
                        content_type="text/html")

    @app.route("/")
    def home():
        return Response("<html><body><a href='/fetch?url=http://example.com'>f</a></body></html>",
                        content_type="text/html")

    @app.route("/fetch")
    def fetch():
        return _serve(request.args.get("url", ""))

    @app.route("/api/preview", methods=["GET", "POST"])
    def preview():
        u = (request.get_json(silent=True) or {}).get("url") if request.is_json else request.args.get("url", "")
        return _serve(u or "")

    return app


class _Server:
    def __init__(self, app):
        self.srv = make_server("127.0.0.1", 0, app, threaded=True)
        self.port = self.srv.server_port
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)

    def __enter__(self):
        self.t.start()
        return f"http://127.0.0.1:{self.port}"

    def __exit__(self, *a):
        self.srv.shutdown()
        self.t.join(timeout=5)


def _scan(base: str) -> list[Finding]:
    cfg = ScanConfig(target=base, modules=MODS, authorized=True, rate_limit=0.0, timeout=8.0)
    return run_scan(parse_target(base), cfg)


def test_ssrf_no_fp_on_echo():
    with _Server(_echo_app()) as base:
        findings = _scan(base)
        bad = [f.title for f in findings if f.module in ("ssrf", "url_preview_ssrf")]
        assert bad == [], f"SSRF false positive on echo-only app: {bad}"


def test_ssrf_detected_on_real_fetch():
    with _Server(_fetcher_app()) as base:
        findings = _scan(base)
        mods = {f.module for f in findings}
        assert "ssrf" in mods or "url_preview_ssrf" in mods, "real metadata SSRF must be detected"
