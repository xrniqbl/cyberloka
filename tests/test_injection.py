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
