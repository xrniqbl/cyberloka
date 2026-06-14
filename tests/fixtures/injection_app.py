"""Deliberately-vulnerable benchmark app for the test suite (LOCAL ONLY).

Every vulnerable endpoint is linked from the homepage so the crawler discovers
the parameters. Used to assert that detection modules find REAL bugs and do not
flag the safe control endpoints.
"""
from __future__ import annotations

import sqlite3
import subprocess

from flask import Flask, request, Response


def create_app() -> Flask:
    app = Flask(__name__)

    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE items(id INTEGER, name TEXT)")
    db.execute("INSERT INTO items VALUES (1, 'Widget')")
    db.commit()

    @app.route("/")
    def home() -> Response:
        return Response(
            "<html><body>"
            "<a href='/search?q=hello'>search</a> "
            "<a href='/item?id=1'>item</a> "
            "<a href='/product?id=1'>product</a> "
            "<a href='/ping?host=127.0.0.1'>ping</a> "
            "<a href='/safe?q=hello'>safe</a>"
            "</body></html>",
            content_type="text/html",
        )

    @app.route("/search")
    def search() -> Response:
        # Reflected XSS: echoes q unescaped.
        q = request.args.get("q", "")
        return Response(f"<html><body>Results: {q}</body></html>",
                        content_type="text/html")

    @app.route("/item")
    def item() -> Response:
        # SQLi (error-based, MySQL-style error string) — for the `sqli` module.
        item_id = request.args.get("id", "")
        if "'" in item_id or '"' in item_id:
            return Response(
                "<html><body>You have an error in your SQL syntax; check the "
                "manual that corresponds to your MySQL server version</body></html>",
                content_type="text/html",
            )
        return Response(f"<html><body>Item {item_id}</body></html>",
                        content_type="text/html")

    @app.route("/product")
    def product() -> Response:
        # REAL SQL injection into SQLite — for the Safe PoC SQLi prover.
        pid = request.args.get("id", "")
        q = f"SELECT id, name FROM items WHERE id = '{pid}'"
        try:
            rows = db.execute(q).fetchall()
            body = "<br>".join(f"{r[0]}:{r[1]}" for r in rows) or "no rows"
        except Exception as e:  # noqa: BLE001
            body = f"SQL error: {e}"
        return Response(f"<html><body>{body}</body></html>",
                        content_type="text/html")

    @app.route("/ping")
    def ping() -> Response:
        # REAL OS command injection — for the Safe PoC RCE prover.
        host = request.args.get("host", "")
        try:
            out = subprocess.run(
                f"echo pinging {host}", shell=True,
                capture_output=True, text=True, timeout=5).stdout
        except Exception as e:  # noqa: BLE001
            out = str(e)
        return Response(f"<html><body><pre>{out}</pre></body></html>",
                        content_type="text/html")

    @app.route("/safe")
    def safe() -> Response:
        # SAFE control: properly escaped, must NOT be flagged.
        from markupsafe import escape
        q = request.args.get("q", "")
        return Response(f"<html><body>Results: {escape(q)}</body></html>",
                        content_type="text/html")

    return app
