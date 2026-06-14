"""Verification matrix: prove active modules only fire on REAL vulns, not predictions.

Each row pairs a SAFE/reflective endpoint (must NOT be flagged) with a genuinely
vulnerable one (must be flagged). Runnable directly (`python tests/test_verification.py`)
and as a pytest test.
"""
import os
import sys
import threading
import subprocess
import time
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.active import sqli, xss, cmdi, lfi, redirect, dirlist


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", headers=None):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query, keep_blank_values=True)
        p = u.path
        if p == "/reflect":
            return self._send(200, f"<html><body>You searched: {html.escape(q.get('cmd',[''])[0])}</body></html>")
        if p == "/exec":
            try:
                out = subprocess.run("echo " + q.get("cmd", [""])[0], shell=True,
                                     capture_output=True, text=True, timeout=20).stdout
            except Exception as e:
                out = str(e)
            return self._send(200, f"<html><body>result: {out}</body></html>")
        if p == "/sqli_static":
            return self._send(200, "<html><body>Tutorial: 'You have an error in your SQL syntax' means...</body></html>")
        if p == "/sqli_err":
            v = q.get("id", ["1"])[0]
            if v.count("'") % 2 == 1:
                return self._send(200, "<html><body>You have an error in your SQL syntax near ''</body></html>")
            return self._send(200, f"<html><body>Product {v} — Widget</body></html>")
        if p == "/sqli_bool":
            v = q.get("id", ["1"])[0]
            if "1=2" in v.replace(" ", ""):
                return self._send(200, "<html><body>No product found.</body></html>")
            return self._send(200, "<html><body>Product Widget. " + ("detail " * 100) + "</body></html>")
        if p == "/xss_textarea":
            return self._send(200, f"<html><body><textarea>{q.get('q',[''])[0]}</textarea></body></html>")
        if p == "/xss_real":
            return self._send(200, f"<html><body><div>Hi {q.get('q',[''])[0]}</div></body></html>")
        if p == "/redir":
            return self._send(302, "go", headers={"Location": q.get("url", [""])[0]})
        if p == "/redir_safe":
            return self._send(302, "go", headers={"Location": "/home"})
        if p == "/files/":
            return self._send(200, '<html><head><title>Index of /files</title></head><body>'
                                    '<h1>Index of /files</h1><a href="../">Parent Directory</a>'
                                    '<a href="a.txt">a.txt</a><a href="b.zip">b.zip</a></body></html>')
        return self._send(200, "<html><body>home</body></html>")


def _run(mod, url):
    return mod.run(parse_target(url), ScanConfig(target=url, rate_limit=0))


def _matrix():
    srv = ThreadingHTTPServer(("127.0.0.1", 8765), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    B = "http://127.0.0.1:8765"
    try:
        cases = [
            ("cmdi reflective (SAFE)", cmdi, "/reflect?cmd=ping", False),
            ("cmdi real exec (VULN)", cmdi, "/exec?cmd=ping", True),
            ("sqli static error (SAFE)", sqli, "/sqli_static?id=1", False),
            ("sqli error-based (VULN)", sqli, "/sqli_err?id=1", True),
            ("sqli boolean (VULN)", sqli, "/sqli_bool?id=1", True),
            ("xss textarea (SAFE)", xss, "/xss_textarea?q=hi", False),
            ("xss reflected (VULN)", xss, "/xss_real?q=hi", True),
            ("redirect safe (SAFE)", redirect, "/redir_safe?url=x", False),
            ("redirect open (VULN)", redirect, "/redir?url=x", True),
            ("dirlist (VULN)", dirlist, "/", True),
        ]
        results = []
        for label, mod, path, expect in cases:
            findings = _run(mod, B + path)
            results.append((label, len(findings) > 0, expect, [f.title for f in findings]))
        return results
    finally:
        srv.shutdown()


def test_verification_matrix():
    for label, got, expect, titles in _matrix():
        assert got == expect, f"{label}: got_finding={got} expected={expect} {titles}"


if __name__ == "__main__":
    rows = _matrix()
    print("\n=== SELF-TEST RESULTS ===")
    allok = True
    for label, got, expect, titles in rows:
        ok = got == expect
        allok = allok and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label:30s} got={got} expected={expect} {titles or ''}")
    print("\nALL PASS" if allok else "\nSOME FAILED")
    sys.exit(0 if allok else 1)
