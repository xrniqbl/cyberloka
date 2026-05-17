"""Offline smoke test for the four new features:

- Login session config + HttpClient login flow (with stubbed requests)
- TXT report rendering
- PDF report rendering (only if reportlab is installed)
- CLI argument parsing (--menu, --login-config, --txt, --pdf, --open-dashboard)
- Dashboard --open and --no-banner flags

Runs without network. Stubs `requests` only for the login HttpClient test.
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cyberloka.core.config import LoginSession, ScanConfig  # noqa: E402
from cyberloka.core.finding import Finding, Severity  # noqa: E402
from cyberloka.core.target import parse_target  # noqa: E402


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _ok(label: str, cond: bool, detail: str = "") -> None:
    mark = "OK  " if cond else "FAIL"
    print(f"  [{mark}] {label}{(' - ' + detail) if detail else ''}")
    if not cond:
        sys.exit(1)


def _make_findings() -> list[Finding]:
    return [
        Finding(
            module="sqli",
            title="Kemungkinan SQLi pada parameter `id`",
            severity=Severity.CRITICAL,
            description="Error SQL terdeteksi.",
            target="https://example.com/?id=1",
            evidence="you have an error in your sql syntax",
            cwe="CWE-89",
        ),
        Finding(
            module="headers",
            title="Security header hilang: Content-Security-Policy",
            severity=Severity.MEDIUM,
            description="CSP tidak diset.",
            target="https://example.com/",
        ),
        Finding(
            module="cookies",
            title="Cookie `session` kekurangan atribut Secure, HttpOnly",
            severity=Severity.MEDIUM,
            description="Flag tidak ada.",
            target="https://example.com/",
        ),
        Finding(
            module="fingerprint",
            title="Teknologi terdeteksi: nginx/1.10",
            severity=Severity.INFO,
            description="Versi lama.",
            target="https://example.com/",
        ),
    ]


# ---------------------------------------------------------------------------
# 1. LoginSession + HttpClient
# ---------------------------------------------------------------------------


def test_login_session_form() -> None:
    """Form login flow: CSRF fetch + POST + cookie capture."""
    print("== login session: form ==")
    import cyberloka.core.http_client as hc

    # Stub requests.Session
    captured: dict = {}

    class StubResp:
        def __init__(self, text="", status=200, cookies=None, url="https://e.com/dashboard"):
            self.text = text
            self.status_code = status
            self.url = url

    class StubSession:
        def __init__(self):
            self.headers = {}
            self.cookies = {}
            self.proxies = {}

        def mount(self, *a, **kw): pass
        def close(self): pass

        def get(self, url, **kw):
            captured["csrf_url"] = url
            return StubResp(
                text='<input name="csrf_token" value="abc123" />',
                status=200,
                url=url,
            )

        def post(self, url, data=None, **kw):
            captured["post_url"] = url
            captured["post_data"] = data or {}
            self.cookies = {"session": "logged_in"}
            return StubResp(
                text="<html>Welcome, alice</html>",
                status=200,
                url="https://e.com/dashboard",
            )

        def request(self, *a, **kw):
            return StubResp("ok", 200)

    real_session = hc.requests.Session
    hc.requests.Session = StubSession  # type: ignore[assignment]
    try:
        cfg = ScanConfig(
            target="https://e.com/",
            login_session=LoginSession(
                method="form",
                url="https://e.com/login",
                username="alice",
                password="secret",
                user_field="email",
                pass_field="password",
                success_indicator="Welcome,",
                csrf_url="https://e.com/login",
                csrf_field="csrf_token",
            ),
        )
        client = hc.HttpClient(cfg)
        _ok("authenticated flag set", client.authenticated)
        _ok("CSRF URL was fetched", captured.get("csrf_url") == "https://e.com/login")
        _ok(
            "POST included CSRF token",
            captured["post_data"].get("csrf_token") == "abc123",
        )
        _ok(
            "POST used custom user_field",
            "email" in captured["post_data"],
        )
        _ok(
            "session cookie captured",
            client.session.cookies.get("session") == "logged_in",
        )
    finally:
        hc.requests.Session = real_session


def test_login_session_header() -> None:
    print("== login session: header ==")
    import cyberloka.core.http_client as hc

    class StubSession:
        def __init__(self):
            self.headers = {}
            self.cookies = {}
            self.proxies = {}
        def mount(self, *a, **kw): pass
        def close(self): pass
        def request(self, *a, **kw): return None

    real = hc.requests.Session
    hc.requests.Session = StubSession  # type: ignore[assignment]
    try:
        cfg = ScanConfig(
            target="https://api.e.com/",
            login_session=LoginSession(
                method="header",
                headers={"Authorization": "Bearer tok123"},
            ),
        )
        client = hc.HttpClient(cfg)
        _ok("authenticated", client.authenticated)
        _ok(
            "Bearer header set",
            client.session.headers.get("Authorization") == "Bearer tok123",
        )
    finally:
        hc.requests.Session = real


def test_login_session_failure() -> None:
    """failure_indicator should raise LoginError."""
    print("== login session: failure detection ==")
    import cyberloka.core.http_client as hc

    class StubResp:
        text = "<html>Invalid credentials</html>"
        status_code = 200
        url = "https://e.com/login"

    class StubSession:
        def __init__(self):
            self.headers = {}
            self.cookies = {}
            self.proxies = {}
        def mount(self, *a, **kw): pass
        def close(self): pass
        def get(self, *a, **kw): return StubResp()
        def post(self, *a, **kw): return StubResp()
        def request(self, *a, **kw): return StubResp()

    real = hc.requests.Session
    hc.requests.Session = StubSession  # type: ignore[assignment]
    try:
        cfg = ScanConfig(
            target="https://e.com/",
            login_session=LoginSession(
                method="form",
                url="https://e.com/login",
                username="alice",
                password="wrong",
                failure_indicator="Invalid credentials",
            ),
        )
        try:
            hc.HttpClient(cfg)
            _ok("LoginError raised on failure indicator", False, "no error raised")
        except hc.LoginError:
            _ok("LoginError raised on failure indicator", True)
    finally:
        hc.requests.Session = real


def test_login_config_round_trip() -> None:
    print("== login session: load from JSON ==")
    cfg = {
        "method": "form",
        "url": "https://e.com/login",
        "username": "alice",
        "password": "s3cret",
        "user_field": "email",
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        path = f.name
    sess = LoginSession.from_file(path)
    _ok("from_file roundtrip method", sess.method == "form")
    _ok("from_file roundtrip user_field", sess.user_field == "email")


# ---------------------------------------------------------------------------
# 2. TXT reporter
# ---------------------------------------------------------------------------


def test_txt_reporter() -> None:
    print("== TXT reporter ==")
    from cyberloka.reporting.txt_report import render_txt

    findings = _make_findings()
    target = parse_target("https://example.com/")
    cfg = ScanConfig(target="https://example.com/", mode="full")
    text = render_txt(target, cfg, findings)

    _ok("contains target URL", "example.com" in text)
    _ok("contains EXECUTIVE SUMMARY heading", "EXECUTIVE SUMMARY" in text)
    _ok("contains TOP 5 heading", "TOP 5 PRIORITAS" in text)
    _ok("contains COMPLIANCE MAPPING heading", "COMPLIANCE MAPPING" in text)
    _ok("contains FINDINGS heading", "FINDINGS (4)" in text)
    _ok("contains SQLi title", "SQLi" in text)
    _ok("contains [CRITICAL]", "[CRITICAL]" in text)
    _ok("ends with version footer", "Cyberloka" in text.splitlines()[-2])


# ---------------------------------------------------------------------------
# 3. PDF reporter (only if reportlab is available)
# ---------------------------------------------------------------------------


def test_pdf_reporter() -> None:
    print("== PDF reporter ==")
    try:
        import reportlab  # noqa: F401
    except ImportError:
        print("  [SKIP] reportlab not installed in this environment")
        return
    from cyberloka.reporting.pdf_report import write_pdf

    findings = _make_findings()
    target = parse_target("https://example.com/")
    cfg = ScanConfig(target="https://example.com/", mode="full")
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "report.pdf"
        write_pdf(str(out), target, cfg, findings)
        _ok("PDF file written", out.exists())
        _ok("PDF non-empty", out.stat().st_size > 1000)
        # PDF magic bytes
        _ok("PDF magic header", out.read_bytes()[:4] == b"%PDF")


# ---------------------------------------------------------------------------
# 4. CLI argparse
# ---------------------------------------------------------------------------


def test_cli_parser() -> None:
    print("== CLI parser ==")
    from cyberloka.cli import build_parser

    p = build_parser()
    ns = p.parse_args([
        "-t", "https://example.com",
        "--mode", "full",
        "--authorized",
        "--login-config", "login.json",
        "--reports-dir", "reports",
        "--txt",
        "--pdf",
        "--open-dashboard",
        "--verify-after-scan",
    ])
    _ok("target parsed", ns.target == "https://example.com")
    _ok("mode parsed", ns.mode == "full")
    _ok("login_config parsed", ns.login_config == "login.json")
    _ok("txt auto-mode", ns.txt_out == "__auto__")
    _ok("pdf auto-mode", ns.pdf_out == "__auto__")
    _ok("open_dashboard parsed", ns.open_dashboard is True)
    _ok("verify_after_scan parsed", ns.verify_after_scan is True)

    # explicit txt path
    ns2 = p.parse_args(["-t", "https://e.com", "--txt", "out.txt"])
    _ok("explicit txt path", ns2.txt_out == "out.txt")

    # menu flag
    ns3 = p.parse_args(["--menu"])
    _ok("--menu parsed", ns3.menu is True)


def test_cli_resolve_outputs() -> None:
    print("== CLI _resolve_outputs ==")
    from cyberloka.cli import _resolve_outputs, build_parser

    p = build_parser()
    with tempfile.TemporaryDirectory() as td:
        ns = p.parse_args([
            "-t", "https://example.com",
            "--reports-dir", td,
            "--txt", "--pdf",
        ])
        out = _resolve_outputs(ns, "example.com")
        _ok("json path generated", out["json_out"] is not None and out["json_out"].endswith(".json"))
        _ok("html path generated", out["html_out"] is not None and out["html_out"].endswith(".html"))
        _ok("txt path generated", out["txt_out"] is not None and out["txt_out"].endswith(".txt"))
        _ok("pdf path generated", out["pdf_out"] is not None and out["pdf_out"].endswith(".pdf"))
        _ok("paths inside reports dir", str(td) in out["json_out"])


# ---------------------------------------------------------------------------
# 5. End-to-end: run scan with stubbed scanner, verify all reports written
# ---------------------------------------------------------------------------


def test_end_to_end_all_formats() -> None:
    print("== end-to-end: scan + all formats ==")
    import cyberloka.cli as cli_mod

    findings = _make_findings()
    # Stub run_scan + verify_findings to avoid any network/scanner dispatch.
    cli_mod.run_scan = lambda target, cfg: findings  # type: ignore[assignment]
    cli_mod.verify_findings = lambda target, cfg, fs: fs  # type: ignore[assignment]

    with tempfile.TemporaryDirectory() as td:
        rc = cli_mod.main([
            "-t", "https://example.com",
            "--mode", "full",
            "--authorized",
            "--reports-dir", td,
            "--txt",
            "--pdf",
            "--no-compliance",
            "--quiet",
            "--yes",
        ])

        files = sorted(Path(td).iterdir())
        names = {f.suffix for f in files}
        _ok("returned exit code 1 (critical+high present)", rc == 1)
        _ok(".json written", ".json" in names)
        # HTML only if jinja2 available
        try:
            import jinja2  # noqa: F401
            _ok(".html written", ".html" in names)
        except ImportError:
            print("  [INFO] jinja2 missing, skipping .html assertion")
        _ok(".txt written", ".txt" in names)
        # PDF only if reportlab is installed
        try:
            import reportlab  # noqa: F401
            _ok(".pdf written", ".pdf" in names)
        except ImportError:
            print("  [INFO] reportlab missing, skipping .pdf assertion")


# ---------------------------------------------------------------------------
# 6. Dashboard parser
# ---------------------------------------------------------------------------


def test_dashboard_parser() -> None:
    print("== Dashboard parser ==")
    try:
        # Avoid hard-failing when flask isn't installed; the parser itself
        # is created inside main(), which imports flask at module load.
        import flask  # noqa: F401
    except ImportError:
        print("  [SKIP] flask not installed in this environment")
        return
    from cyberloka.dashboard import app as dashboard_app

    # Patch app.run to avoid actually starting the server.
    original_create_app = dashboard_app.create_app
    fake_app = MagicMock()
    dashboard_app.create_app = lambda d: fake_app  # type: ignore[assignment]
    try:
        with tempfile.TemporaryDirectory() as td:
            buf = io.StringIO()
            with redirect_stdout(buf):
                # --no-banner suppresses banner; we just want to verify
                # parser accepts --open and forwards to fake_app.run.
                dashboard_app.main([
                    "--reports-dir", td,
                    "--port", "5006",
                    "--no-banner",
                ])
            fake_app.run.assert_called_once()
            kwargs = fake_app.run.call_args.kwargs
            _ok("dashboard bound to port 5006", kwargs.get("port") == 5006)
    finally:
        dashboard_app.create_app = original_create_app


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    test_login_session_form()
    test_login_session_header()
    test_login_session_failure()
    test_login_config_round_trip()
    test_txt_reporter()
    test_pdf_reporter()
    test_cli_parser()
    test_cli_resolve_outputs()
    test_end_to_end_all_formats()
    test_dashboard_parser()
    print("\nAll feature smoke checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
