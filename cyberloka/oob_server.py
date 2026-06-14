"""Self-hostable OOB (OAST) collaborator server for cyberloka.

Run this on a publicly-reachable host you control:

    python -m cyberloka.oob_server --host 0.0.0.0 --port 8088

Then point the scanner at it:

    cyberloka -t https://target --mode active --authorized \
        --oob-url http://your-collaborator:8088

Any inbound HTTP request is recorded, keyed by the unique token found in
the request (path segment, subdomain, or query string). The scanner polls
`/_cyberloka/poll/<token>` to confirm a blind callback fired.

This server is intentionally passive: it only records that a request
arrived. It serves no payloads and performs no actions on anyone.
"""
from __future__ import annotations

import argparse
import re
import threading
import time
from collections import defaultdict

from flask import Flask, jsonify, request

TOKEN_RE = re.compile(r"cl[0-9a-f]{16}")

app = Flask(__name__)
_hits: dict[str, list[dict]] = defaultdict(list)
_lock = threading.Lock()


def _record(token: str, meta: dict) -> None:
    with _lock:
        _hits[token].append(meta)


def _extract_tokens(req) -> set[str]:
    blob = " ".join(
        [req.path, req.host, req.query_string.decode("latin-1", "ignore")]
    )
    return set(TOKEN_RE.findall(blob))


@app.route("/_cyberloka/poll/<token>")
def poll(token: str):
    with _lock:
        return jsonify({"token": token, "hits": list(_hits.get(token, []))})


@app.route("/", defaults={"path": ""},
           methods=["GET", "POST", "PUT", "HEAD", "OPTIONS"])
@app.route("/<path:path>",
           methods=["GET", "POST", "PUT", "HEAD", "OPTIONS"])
def catch_all(path: str):
    meta = {
        "ts": time.time(),
        "method": request.method,
        "path": "/" + path,
        "host": request.host,
        "remote": request.remote_addr,
        "ua": request.headers.get("User-Agent", ""),
    }
    for token in _extract_tokens(request):
        _record(token, meta)
    return jsonify({"ok": True}), 200


def main() -> None:
    ap = argparse.ArgumentParser(description="cyberloka OOB collaborator server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8088)
    args = ap.parse_args()
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
