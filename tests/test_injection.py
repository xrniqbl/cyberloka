"""Functional detection tests against the vulnerable benchmark app.

Asserts real bugs are detected AND the safe control endpoint is not flagged.
"""
from __future__ import annotations


def _modules(findings, module):
    return [f for f in findings if f.module == module]


def test_reflected_xss_detected(injection_url, scan):
    findings = scan(injection_url, ["crawler", "xss"])
    xss = _modules(findings, "xss")
    assert xss, "reflected XSS on /search should be detected"
    # the safe, escaped /safe endpoint must not be the one flagged
    assert all("/safe" not in f.target for f in xss), "must not flag escaped /safe"


def test_sqli_error_based_detected(injection_url, scan):
    findings = scan(injection_url, ["crawler", "sqli"])
    sqli = _modules(findings, "sqli")
    assert sqli, "error-based SQLi on /item should be detected"
    assert any(f.confidence in ("firm", "confirmed") for f in sqli)


def test_no_false_positive_on_safe_endpoint(injection_url, scan):
    # A scan limited to the escaped endpoint surface should not invent XSS.
    findings = scan(injection_url, ["crawler", "xss", "sqli"])
    for f in findings:
        assert "/safe?" not in f.target, f"false positive on safe endpoint: {f.title}"


def test_form_based_xss_detected(injection_url, scan):
    findings = scan(injection_url, ["crawler", "xss"])
    xss = _modules(findings, "xss")
    assert any("/comment" in f.target for f in xss), \
        "reflected XSS via the POST /comment form should be detected"


def test_form_based_sqli_detected(injection_url, scan):
    findings = scan(injection_url, ["crawler", "sqli"])
    sqli = _modules(findings, "sqli")
    assert any("/login" in f.target for f in sqli), \
        "error-based SQLi via the POST /login form should be detected"


def test_dangerous_form_is_skipped(injection_url):
    # fuzz_forms must never submit a destructive-looking form (e.g. /logout).
    from cyberloka.active._helpers import fuzz_forms
    from cyberloka.core import HttpClient
    from cyberloka.core.config import ScanConfig
    from cyberloka.core.target import parse_target
    from cyberloka.recon import crawler

    cfg = ScanConfig(target=injection_url, authorized=True, rate_limit=0.0)
    tgt = parse_target(injection_url)
    crawler.run(tgt, cfg)
    client = HttpClient(cfg)
    actions = [action for _f, action, _r in fuzz_forms(client, cfg, "probe")]
    client.close()
    assert actions, "expected at least one fuzzable form"
    assert all("/logout" not in a for a in actions), \
        "the /logout form must be skipped by the safety guard"
