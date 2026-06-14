"""Tier-1 verification: nosqli / xpath / ldap must NOT fire on static mentions,
but MUST fire when the error is genuinely triggered by the injection payload.

FP trap app: every page statically mentions 'xpath/ldap/mongo' and shows a 'logout'
link (so naive 'keyword in body' / 'success word in body' logic would false-positive).
Real-vuln app: error/success appears ONLY in response to the breaking payload.
"""
import threading
from collections.abc import Iterator

import pytest
from flask import Flask, Response, request
from werkzeug.serving import make_server

from cyberloka.core import Finding
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.scanner import run_scan

MODS = ["crawler", "nosqli", "xpath_injection", "ldap_injection"]


def _fp_trap_app() -> Flask:
    app = Flask(__name__)
    NOISE = "xpath ldap mongodb bson search filter logout welcome dashboard"

    @app.route("/")
    def home():
        return Response(
            f"<html><body>{NOISE}"
            "<a href='/find?q=hello'>find</a>"
            "<form action='/login' method='post'>"
            "<input name='user'><input name='password' type='password'>"
            "<input type='submit'></form></body></html>",
            content_type="text/html")

    @app.route("/find")
    def find():
        # Selalu memuat kata-kata error, tanpa peduli input (mention statis).
        return Response(f"<html><body>Result. {NOISE} XPathException</body></html>",
                        content_type="text/html")

    @app.route("/login", methods=["POST"])
    def login():
        # Halaman sama untuk input apa pun: ada 'welcome/dashboard/logout' + kata error.
        return Response(f"<html><body>{NOISE} invalid dn</body></html>",
                        content_type="text/html")

    return app


def _real_vuln_app() -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def home():
        return Response(
            "<html><body><a href='/find?q=hello'>find</a>"
            "<form action='/login' method='post'>"
            "<input name='user'><input name='password' type='password'>"
            "<input type='submit'></form></body></html>",
            content_type="text/html")

    @app.route("/find")
    def find():
        q = request.args.get("q", "")
        if any(c in q for c in ("'", "*", "]")) or " or " in q:
            return Response("<html><body>XPath syntax error: XPathException near token</body></html>",
                            content_type="text/html")
        return Response(f"<html><body>Result: {q}</body></html>", content_type="text/html")

    @app.route("/login", methods=["POST"])
    def login():
        if request.is_json:
            data = request.get_json(silent=True) or {}
            if any(isinstance(v, dict) for v in data.values()):  # NoSQL operator
                return Response("<html><body>Welcome to your dashboard. logout</body></html>",
                                content_type="text/html")
            return Response("<html><body>login failed</body></html>", content_type="text/html")
        user = request.form.get("user", "")
        if "*)(" in user or ")(" in user:
            return Response("<html><body>LDAP error: invalid DN, search filter failed</body></html>",
                            content_type="text/html")
        return Response("<html><body>login failed</body></html>", content_type="text/html")

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


def test_no_false_positive_on_static_mentions():
    with _Server(_fp_trap_app()) as base:
        findings = _scan(base)
        offenders = [f.title for f in findings if f.module in ("nosqli", "xpath_injection", "ldap_injection")]
        assert offenders == [], f"false positives on static-mention app: {offenders}"


def test_real_injections_detected():
    with _Server(_real_vuln_app()) as base:
        findings = _scan(base)
        mods = {f.module for f in findings}
        assert "xpath_injection" in mods, "real XPath injection must be detected"
        assert "ldap_injection" in mods, "real LDAP injection must be detected"
        assert "nosqli" in mods, "real NoSQL auth bypass must be detected"
