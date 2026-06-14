"""Catch-all / soft-404 false-positive matrix.

Membuktikan modul "cek keberadaan" TIDAK menandai situs SPA yang membalas HTTP 200 +
index.html untuk path APA PUN (kasus nyata: snaptix.id menandai /.env palsu), DAN tetap
menandai file/endpoint yang benar-benar terekspos.
"""
import os
import sys
import threading
import time
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.core import probe
from cyberloka.recon import framework_default, source_leak, api_discovery
from cyberloka.passive import sensitive_files

SPA_HTML = ("<!doctype html><html><head><title>SnapTix</title></head>"
            "<body><div id=root>app=loaded; config={a:1}; key=value</div>"
            "<script src=/_next/static/app.js></script></body></html>")


class _SPA(BaseHTTPRequestHandler):
    """Returns 200 + same SPA HTML for EVERY path (classic SPA catch-all)."""
    def log_message(self, *a):
        pass

    def do_GET(self):
        b = SPA_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    do_POST = do_GET


class _RealLeak(BaseHTTPRequestHandler):
    """A site that 404s unknown paths but truly exposes /.env and /.git/config."""
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain"):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/":
            return self._send(200, "<html><body>home</body></html>", "text/html")
        if p == "/.env":
            return self._send(200, "APP_KEY=base64:abcd\nDB_PASSWORD=s3cret\nDB_HOST=localhost\n")
        if p == "/.git/config":
            return self._send(200, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@x\n")
        return self._send(404, "<html><body>Not Found</body></html>", "text/html")


def _serve(handler, port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _cfg(url):
    return ScanConfig(target=url, rate_limit=0)


def test_spa_catchall_produces_no_false_positives():
    probe.reset_cache()
    srv = _serve(_SPA, 8801)
    time.sleep(0.3)
    base = "http://127.0.0.1:8801"
    try:
        for mod in (framework_default, source_leak, api_discovery, sensitive_files):
            findings = mod.run(parse_target(base), _cfg(base))
            assert findings == [], f"{mod.__name__} false-positive on SPA catch-all: {[f.title for f in findings]}"
    finally:
        srv.shutdown()


def test_real_exposed_files_are_detected():
    probe.reset_cache()
    srv = _serve(_RealLeak, 8802)
    time.sleep(0.3)
    base = "http://127.0.0.1:8802"
    try:
        sl = source_leak.run(parse_target(base), _cfg(base))
        assert any("/.env" in f.target for f in sl), "real exposed .env must be detected"
        assert any(".git/config" in f.target for f in sl), "real exposed .git/config must be detected"
        fd = framework_default.run(parse_target(base), _cfg(base))
        assert any("/.env" in f.target for f in fd), "framework_default must detect real .env"
    finally:
        srv.shutdown()


if __name__ == "__main__":
    probe.reset_cache()
    s1 = _serve(_SPA, 8801); time.sleep(0.3)
    b = "http://127.0.0.1:8801"
    print("=== SPA catch-all (must be empty) ===")
    for mod in (framework_default, source_leak, api_discovery, sensitive_files):
        fs = mod.run(parse_target(b), _cfg(b))
        print(f"[{'PASS' if not fs else 'FAIL'}] {mod.__name__:28s} findings={[f.title for f in fs]}")
    s1.shutdown()
    probe.reset_cache()
    s2 = _serve(_RealLeak, 8802); time.sleep(0.3)
    b2 = "http://127.0.0.1:8802"
    print("\n=== Real exposed files (must detect) ===")
    sl = source_leak.run(parse_target(b2), _cfg(b2))
    print(f"[{'PASS' if any('/.env' in f.target for f in sl) else 'FAIL'}] source_leak .env  {[f.target for f in sl]}")
    s2.shutdown()
