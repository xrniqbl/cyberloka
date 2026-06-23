"""Regresi sensitive_files: HTTP 200 + nama path TIDAK cukup untuk CRITICAL.

Akar false-positive (simkopdes /.env): server Next.js membalas halaman HTML
untuk path apa pun, sehingga /.env dilaporkan KRITIS + confirmed padahal tak
ada isi .env. Modul kini wajib membuktikan tanda-tangan konten file.

Mandiri — hanya butuh stdlib http.server.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.passive import sensitive_files

# Halaman SPA Next.js generik yang dibalas untuk SEMUA path (catch-all 200).
NEXT_SHELL = (
    "<!DOCTYPE html><html lang=\"id\"><head><meta charset=\"utf-8\">"
    "<title>SIMKOPDES</title><script src=\"/_next/static/chunks/main.js\">"
    "</script></head><body><div id=\"__next\"></div>"
    "<script>self.__next_f=[]</script></body></html>"
).encode()


def _make_handler(routes: dict, default_spec=None, default_status: int = 404):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            spec = routes.get(path)
            if spec is None and default_spec is not None:
                body, ctype = default_spec
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if spec is None:
                self.send_response(default_status)
                self.end_headers()
                self.wfile.write(b"not found")
                return
            body, ctype = spec
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def _serve(routes: dict, default_spec=None, default_status: int = 404) -> Iterator[str]:
    srv = HTTPServer(("127.0.0.1", 0), _make_handler(routes, default_spec, default_status))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        t.join(timeout=5)


def _run(base: str):
    cfg = ScanConfig(target=base, authorized=True, rate_limit=0.0)
    return sensitive_files.run(parse_target(base), cfg)


# --- FP utama: SPA membalas HTML untuk SEMUA path (termasuk /.env) ----------
@pytest.fixture()
def spa_catchall_url() -> Iterator[str]:
    # default_spec = setiap path balas shell HTML 200 (perilaku Next.js statis).
    yield from _serve({}, default_spec=(NEXT_SHELL, "text/html; charset=utf-8"))


def test_spa_catchall_env_not_flagged(spa_catchall_url):
    findings = _run(spa_catchall_url)
    bad = [f for f in findings if ".env" in f.target.lower()]
    assert bad == [], "/.env yang balas HTML SPA TIDAK boleh dilaporkan"


def test_spa_catchall_no_confirmed_critical(spa_catchall_url):
    findings = _run(spa_catchall_url)
    confirmed_crit = [
        f for f in findings
        if f.confidence == "confirmed" and f.severity.value == "critical"
    ]
    assert confirmed_crit == [], (
        "Tidak boleh ada CRITICAL+confirmed dari catch-all SPA shell"
    )


# --- FP varian: random path 404, tapi /.env tetap balas beranda HTML --------
@pytest.fixture()
def spa_env_html_url() -> Iterator[str]:
    # Path random -> 404; /.env -> beranda HTML (control-diff lama lolos).
    yield from _serve(
        {"/.env": (NEXT_SHELL, "text/html; charset=utf-8")},
        default_status=404,
    )


def test_env_returns_html_homepage_rejected(spa_env_html_url):
    findings = _run(spa_env_html_url)
    bad = [f for f in findings if ".env" in f.target.lower()]
    assert bad == [], "/.env berisi HTML (bukan KEY=VALUE) harus ditolak"


# --- True positive: /.env asli berisi KEY=VALUE -----------------------------
@pytest.fixture()
def real_env_url() -> Iterator[str]:
    env = (
        b"APP_ENV=production\n"
        b"DB_HOST=10.0.0.5\n"
        b"DB_PASSWORD=SuperSecret123\n"
        b"STRIPE_SECRET=sk_live_abcdef0123456789\n"
    )
    yield from _serve({"/.env": (env, "text/plain")}, default_status=404)


def test_real_env_is_confirmed_critical(real_env_url):
    findings = _run(real_env_url)
    env_f = [f for f in findings if f.target.lower().endswith("/.env")]
    assert len(env_f) == 1
    assert env_f[0].severity.value == "critical"
    assert env_f[0].confidence == "confirmed"


# --- True positive: private key ---------------------------------------------
@pytest.fixture()
def real_key_url() -> Iterator[str]:
    key = (
        b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        b"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n"
        b"-----END OPENSSH PRIVATE KEY-----\n"
    )
    yield from _serve({"/id_rsa": (key, "application/octet-stream")}, default_status=404)


def test_real_private_key_confirmed(real_key_url):
    findings = _run(real_key_url)
    f = [x for x in findings if x.target.lower().endswith("/id_rsa")]
    assert len(f) == 1 and f[0].confidence == "confirmed"
    assert f[0].severity.value == "critical"


# --- True positive: SQL dump ------------------------------------------------
@pytest.fixture()
def real_sql_url() -> Iterator[str]:
    sql = (
        b"-- MySQL dump 10.13\n"
        b"CREATE TABLE users (id INT, pass VARCHAR(255));\n"
        b"INSERT INTO users VALUES (1, 'hash');\n"
    )
    yield from _serve({"/backup.sql": (sql, "application/sql")}, default_status=404)


def test_real_sql_dump_confirmed(real_sql_url):
    findings = _run(real_sql_url)
    f = [x for x in findings if x.target.lower().endswith("/backup.sql")]
    assert len(f) == 1 and f[0].confidence == "confirmed"


# --- public file: robots.txt tidak dilaporkan sebagai sensitif --------------
@pytest.fixture()
def robots_url() -> Iterator[str]:
    yield from _serve(
        {"/robots.txt": (b"User-agent: *\nDisallow:\n", "text/plain")},
        default_status=404,
    )


def test_robots_not_flagged(robots_url):
    findings = _run(robots_url)
    assert [f for f in findings if "robots.txt" in f.target] == []
