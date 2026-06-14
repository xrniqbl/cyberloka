"""Web Cache Deception benchmark: origin behind a shared cache (LOCAL ONLY).

- session=victim cookie  => logged in as victim@example.com
- /account/<x>.css       : origin WRONGLY caches the account page (vulnerable)
- /profile/<x>.css       : origin correctly sends private,no-store (safe control)
"""
from __future__ import annotations

import re

from flask import Flask, request, Response

STATIC_RE = re.compile(r"\.(css|js|png|jpg|ico|svg|woff)$", re.I)


def create_app() -> Flask:
    app = Flask(__name__)
    cache: dict[str, tuple[str, dict]] = {}

    def authed() -> bool:
        return request.cookies.get("session") == "victim"

    def account_body() -> str:
        if authed():
            return ("<html><body><h1>Account</h1>"
                    "<p>Email: victim@example.com</p>"
                    "<a href='/logout'>Logout</a></body></html>")
        return "<html><body><h1>Please log in</h1></body></html>"

    def origin(kind: str) -> tuple[str, dict]:
        body = account_body()
        is_static = bool(STATIC_RE.search(request.path))
        if kind == "account" and is_static:
            cc = "public, max-age=60"        # the bug
        else:
            cc = "private, no-store"         # correct
        return body, {"Cache-Control": cc, "Content-Type": "text/html"}

    def through_cache(kind: str) -> Response:
        path = request.full_path.rstrip("?")
        if path in cache:
            body, headers = cache[path]
            h = dict(headers); h["X-Cache"] = "HIT"; h["Age"] = "5"
            return Response(body, headers=h)
        body, headers = origin(kind)
        cc = headers.get("Cache-Control", "").lower()
        cacheable = ("public" in cc or re.search(r"max-age=[1-9]", cc)) \
            and "no-store" not in cc and "private" not in cc
        h = dict(headers)
        if cacheable and STATIC_RE.search(request.path):
            cache[path] = (body, headers); h["X-Cache"] = "MISS"
        else:
            h["X-Cache"] = "BYPASS"
        return Response(body, headers=h)

    @app.route("/")
    def home() -> Response:
        return Response(
            "<html><body><a href='/account'>account</a> "
            "<a href='/profile'>profile</a></body></html>",
            content_type="text/html")

    @app.route("/account")
    @app.route("/account/<path:sub>")
    def account(sub: str = "") -> Response:
        return through_cache("account")

    @app.route("/profile")
    @app.route("/profile/<path:sub>")
    def profile(sub: str = "") -> Response:
        return through_cache("profile")

    return app
