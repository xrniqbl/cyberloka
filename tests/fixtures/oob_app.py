"""Flask fixtures for OOB (blind SSRF) testing.

- vuln app: performs a server-side fetch of the `url` param (blind SSRF).
- safe app: echoes the `url` param, never makes an outbound request.
"""
from __future__ import annotations

import requests
from flask import Flask, request


def create_vuln_app() -> Flask:
    app = Flask("oob_vuln")

    @app.route("/")
    def home():
        return '<a href="/fetch?url=http://example.com/img.png">img</a>'

    @app.route("/fetch")
    def fetch():
        u = request.args.get("url", "")
        if u:
            try:
                requests.get(u, timeout=3)
            except requests.RequestException:
                pass
        return "ok"

    return app


def create_safe_app() -> Flask:
    app = Flask("oob_safe")

    @app.route("/")
    def home():
        return '<a href="/fetch?url=http://example.com/img.png">img</a>'

    @app.route("/fetch")
    def fetch():
        return "url=" + request.args.get("url", "")

    return app
