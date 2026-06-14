"""Tier-3 verification: auth_bypass (admin paths) and mass_assignment must not
false-positive on SPA catch-all / generic echo, but must catch the real thing.
"""
import threading

import pytest
from flask import Flask, Response, request, jsonify
from werkzeug.serving import make_server

from cyberloka.core import Finding
from cyberloka.core import probe
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.scanner import run_scan
from cyberloka.active import auth_bypass

SPA = "<!doctype html><html><body>app login dashboard admin username password</body></html>"


def _spa_app() -> Flask:
    app = Flask(__name__)

    @app.route("/", defaults={"_p": ""})
    @app.route("/<path:_p>")
    def any_path(_p):
        return Response(SPA, content_type="text/html")  # same 200 page for EVERY path

    return app


def _real_admin_app() -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def home():
        return Response("<html><body>home</body></html>", content_type="text/html")

    @app.route("/admin")
    def admin():
        return Response("<html><body><form>Admin Login<input type='password' name='pw'>"
                        "<input name='username'></form></body></html>", content_type="text/html")

    @app.errorhandler(404)
    def nf(e):
        return Response("<html><body>Not Found</body></html>", status=404, content_type="text/html")

    return app


def _mass_fp_app() -> Flask:
    """Generic page that ALWAYS mentions role/is_admin regardless of input."""
    app = Flask(__name__)

    @app.route("/")
    def home():
        return Response("<html><body><form action='/register' method='post'>"
                        "<input name='email'><input type='password' name='pw'>"
                        "<input type='submit'></form></body></html>", content_type="text/html")

    @app.route("/register", methods=["POST"])
    def register():
        return Response("<html><body>Welcome! role: admin, is_admin: true (static)</body></html>",
                        content_type="text/html")

    return app


def _mass_real_app() -> Flask:
    """Reflects submitted fields back as JSON (accepts whatever you send)."""
    app = Flask(__name__)

    @app.route("/")
    def home():
        return Response("<html><body><form action='/register' method='post'>"
                        "<input name='email'><input type='password' name='pw'>"
                        "<input type='submit'></form></body></html>", content_type="text/html")

    @app.route("/register", methods=["POST"])
    def register():
        return jsonify({k: v for k, v in request.form.items()})

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


def test_auth_bypass_admin_no_fp_on_spa():
    probe.reset_cache()
    with _Server(_spa_app()) as base:
        cfg = ScanConfig(target=base, rate_limit=0.0, timeout=8.0)
        findings = auth_bypass.run(parse_target(base), cfg)
        admin_pages = [f for f in findings if "admin/internal" in f.title]
        assert admin_pages == [], f"SPA catch-all wrongly flagged as admin page: {[f.target for f in admin_pages]}"


def test_auth_bypass_admin_detected_when_real():
    probe.reset_cache()
    with _Server(_real_admin_app()) as base:
        cfg = ScanConfig(target=base, rate_limit=0.0, timeout=8.0)
        findings = auth_bypass.run(parse_target(base), cfg)
        assert any("/admin" in f.target for f in findings), "real exposed admin login must be detected"


def test_mass_assignment_no_fp_on_static_echo():
    with _Server(_mass_fp_app()) as base:
        cfg = ScanConfig(target=base, modules=["crawler", "mass_assignment"], authorized=True, rate_limit=0.0, timeout=8.0)
        findings = run_scan(parse_target(base), cfg)
        assert [f for f in findings if f.module == "mass_assignment"] == [], "static echo must not be flagged"


def test_mass_assignment_detected_when_reflected():
    with _Server(_mass_real_app()) as base:
        cfg = ScanConfig(target=base, modules=["crawler", "mass_assignment"], authorized=True, rate_limit=0.0, timeout=8.0)
        findings = run_scan(parse_target(base), cfg)
        assert any(f.module == "mass_assignment" for f in findings), "accepted privilege field must be detected"
