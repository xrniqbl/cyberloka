"""Offline smoke test for the verification (deep re-scan) module.

Mocks HttpClient so the test runs without any network. Validates each
verifier dispatches correctly, classifies status sensibly, and produces a
PoC string when applicable.
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cyberloka.active.verify as V  # noqa: E402


class FakeResp:
    def __init__(self, text: str = "", status_code: int = 200, headers: dict | None = None):
        self.text = text
        self.content = text.encode() if text else b""
        self.status_code = status_code
        self.headers = headers or {}


class FakeClient:
    def __init__(self, scenario):
        self.scenario = scenario

    def _decoded_query(self, url: str) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}

    def get(self, url, **kw):
        return self.scenario(url, self._decoded_query(url), method="GET", **kw)

    def post(self, url, **kw):
        return self.scenario(url, self._decoded_query(url), method="POST", **kw)

    def request(self, method, url, **kw):
        return self.scenario(url, self._decoded_query(url), method=method, **kw)

    def head(self, url, **kw):
        return self.scenario(url, self._decoded_query(url), method="HEAD", **kw)

    def options(self, url, **kw):
        return self.scenario(url, self._decoded_query(url), method="OPTIONS", **kw)

    def close(self):
        pass


def assert_status(name: str, got: str, want: tuple[str, ...]) -> None:
    ok = got in want
    print(f"  [{'OK' if ok else 'FAIL'}] {name}: status={got} (want one of {want})")
    if not ok:
        sys.exit(1)


def test_sqli_error_based() -> None:
    """SQL error message returned when payload contains a quote."""
    def scenario(url, qs, **kw):
        v = qs.get("id", "")
        if any(c in v for c in ("'", '"')):
            return FakeResp(
                "<html>You have an error in your SQL syntax near 'foo'</html>", 500
            )
        return FakeResp("normal page content" * 40, 200)

    res = V._verify_sqli(FakeClient(scenario), {
        "target": "https://e.com/q?id=5", "title": "SQLi `id`",
    })
    assert_status("sqli error-based", res.status, ("firm", "confirmed"))


def test_sqli_clean() -> None:
    def scenario(url, qs, **kw):
        return FakeResp("welcome", 200)
    res = V._verify_sqli(FakeClient(scenario), {
        "target": "https://e.com/q?id=5", "title": "SQLi `id`",
    })
    assert_status("sqli clean (false positive)", res.status, ("false_positive",))


def test_xss_reflected() -> None:
    def scenario(url, qs, **kw):
        v = qs.get("q", "")
        return FakeResp(f"<html><body>Hello {v}</body></html>", 200)
    res = V._verify_xss(FakeClient(scenario), {
        "target": "https://e.com/?q=test", "title": "XSS `q`",
    })
    assert_status("xss reflected", res.status, ("firm", "confirmed"))


def test_xss_encoded() -> None:
    import html
    def scenario(url, qs, **kw):
        v = qs.get("q", "")
        return FakeResp(f"<html><body>Hello {html.escape(v)}</body></html>", 200)
    res = V._verify_xss(FakeClient(scenario), {
        "target": "https://e.com/?q=test", "title": "XSS `q`",
    })
    assert_status("xss encoded (false positive)", res.status, ("false_positive",))


def test_lfi() -> None:
    def scenario(url, qs, **kw):
        v = qs.get("file", "")
        if "etc/passwd" in v.lower() or "etc%2fpasswd" in v.lower():
            return FakeResp("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:", 200)
        return FakeResp("ok", 200)
    res = V._verify_lfi(FakeClient(scenario), {
        "target": "https://e.com/?file=index", "title": "LFI `file`",
    })
    assert_status("lfi", res.status, ("confirmed",))


def test_redirect() -> None:
    def scenario(url, qs, method="GET", **kw):
        v = qs.get("url", "")
        if "evil.example.org" in v:
            return FakeResp("", 302, {"Location": "https://evil.example.org/"})
        return FakeResp("ok", 200)
    res = V._verify_redirect(FakeClient(scenario), {
        "target": "https://e.com/?url=/", "title": "Redirect `url`",
    })
    assert_status("open redirect", res.status, ("firm", "confirmed"))


def test_sensitive_file() -> None:
    def scenario(url, qs, **kw):
        return FakeResp("DB_PASSWORD=hunter2\nAPI_KEY=abc\nDEBUG=true", 200)
    res = V._verify_sensitive_file(FakeClient(scenario), {
        "target": "https://e.com/.env", "title": "Sensitive .env",
    })
    assert_status("sensitive .env", res.status, ("confirmed",))


def test_sensitive_file_404() -> None:
    def scenario(url, qs, **kw):
        return FakeResp("Not Found", 404)
    res = V._verify_sensitive_file(FakeClient(scenario), {
        "target": "https://e.com/.env", "title": "Sensitive .env",
    })
    assert_status("sensitive 404 (resolved)", res.status, ("false_positive",))


def test_headers_now_present() -> None:
    def scenario(url, qs, **kw):
        return FakeResp("", 200, {"Content-Security-Policy": "default-src 'self'"})
    res = V._verify_headers(FakeClient(scenario), {
        "target": "https://e.com/",
        "title": "Security header hilang: Content-Security-Policy",
    })
    assert_status("header now present (CDN flake -> fp)", res.status, ("false_positive",))


def test_headers_still_absent() -> None:
    def scenario(url, qs, **kw):
        return FakeResp("", 200, {})
    res = V._verify_headers(FakeClient(scenario), {
        "target": "https://e.com/",
        "title": "Security header hilang: Content-Security-Policy",
    })
    assert_status("header still absent", res.status, ("confirmed",))


def test_cookies_fixed() -> None:
    def scenario(url, qs, **kw):
        return FakeResp("", 200, {"Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Strict"})
    res = V._verify_cookies(FakeClient(scenario), {
        "target": "https://e.com/",
        "title": "Cookie `session` kekurangan atribut keamanan",
    })
    assert_status("cookie fixed", res.status, ("false_positive",))


def test_cookies_bad() -> None:
    def scenario(url, qs, **kw):
        return FakeResp("", 200, {"Set-Cookie": "session=abc"})
    res = V._verify_cookies(FakeClient(scenario), {
        "target": "https://e.com/",
        "title": "Cookie `session` kekurangan atribut keamanan",
    })
    assert_status("cookie still bad", res.status, ("confirmed",))


def test_dirlist_confirmed() -> None:
    def scenario(url, qs, **kw):
        return FakeResp(
            "<html><head><title>Index of /backup</title></head>"
            "<body><h1>Index of /backup</h1>"
            "<a href=../>Parent Directory</a></body></html>",
            200,
        )
    res = V._verify_dirlist(FakeClient(scenario), {
        "target": "https://e.com/backup/", "title": "Directory listing",
    })
    assert_status("dirlist confirmed", res.status, ("confirmed",))


def test_dirlist_resolved() -> None:
    def scenario(url, qs, **kw):
        return FakeResp("<h1>Welcome</h1>", 200)
    res = V._verify_dirlist(FakeClient(scenario), {
        "target": "https://e.com/backup/", "title": "Directory listing",
    })
    assert_status("dirlist resolved", res.status, ("false_positive",))


def test_load_bundle_round_trip(tmp_path: Path | None = None) -> None:
    """Write a synthetic bundle then load it back through verify.load_findings_from_bundle."""
    import json
    import tempfile
    from cyberloka.core.config import ScanConfig
    from cyberloka.core.finding import Finding, Severity
    from cyberloka.core.report_bundle import build_bundle
    from cyberloka.core.target import parse_target

    findings = [
        Finding(module="sqli", title="SQLi `id`", severity=Severity.CRITICAL,
                description="x", target="https://e.com/?id=1", cwe="CWE-89"),
        Finding(module="headers", title="Security header hilang: Content-Security-Policy",
                severity=Severity.MEDIUM, description="x", target="https://e.com/"),
    ]
    target = parse_target("https://e.com/")
    cfg = ScanConfig(target="https://e.com/", mode="passive")
    bundle = build_bundle(target, cfg, findings)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(bundle, f)
        path = f.name
    t2, fs2 = V.load_findings_from_bundle(path)
    assert t2.host == "e.com"
    assert len(fs2) == 2
    assert fs2[0].module in ("sqli", "headers")
    print("  [OK] load_findings_from_bundle round-trip")


def test_end_to_end_verify(tmp_path: Path | None = None) -> None:
    """Run verify_findings() end-to-end with a fake client and check side effects."""
    from cyberloka.core.config import ScanConfig
    from cyberloka.core.finding import Finding, Severity
    from cyberloka.core.target import parse_target

    findings = [
        Finding(module="headers",
                title="Security header hilang: Content-Security-Policy",
                severity=Severity.MEDIUM, description="x", target="https://e.com/"),
        Finding(module="dns", title="some recon", severity=Severity.INFO,
                description="x", target="e.com"),  # unsupported -> passthrough
    ]

    # Replace HttpClient inside the module so we don't touch the network.
    class StubClient:
        def __init__(self, *a, **kw): pass
        def get(self, url, **kw): return FakeResp("", 200, {})  # missing CSP
        def post(self, url, **kw): return FakeResp("", 200, {})
        def request(self, *a, **kw): return FakeResp("", 200, {})
        def head(self, url, **kw): return FakeResp("", 200, {})
        def options(self, url, **kw): return FakeResp("", 200, {})
        def close(self): pass

    original = V.HttpClient
    V.HttpClient = StubClient
    try:
        out = V.verify_findings(parse_target("https://e.com/"),
                                ScanConfig(target="https://e.com/", mode="passive"),
                                findings)
    finally:
        V.HttpClient = original

    assert len(out) == 2
    h = next(f for f in out if f.module == "headers")
    assert h.confidence == "confirmed"
    assert h.extra and "verification" in h.extra
    assert h.extra["verification"]["status"] == "confirmed"
    dns = next(f for f in out if f.module == "dns")
    assert "verification" not in (dns.extra or {})
    print("  [OK] end-to-end verify (header + unsupported passthrough)")


def main() -> int:
    print("== verifier unit checks ==")
    test_sqli_error_based()
    test_sqli_clean()
    test_xss_reflected()
    test_xss_encoded()
    test_lfi()
    test_redirect()
    test_sensitive_file()
    test_sensitive_file_404()
    test_headers_now_present()
    test_headers_still_absent()
    test_cookies_fixed()
    test_cookies_bad()
    test_dirlist_confirmed()
    test_dirlist_resolved()
    print("== integration ==")
    test_load_bundle_round_trip()
    test_end_to_end_verify()
    print("\nAll verify smoke checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
