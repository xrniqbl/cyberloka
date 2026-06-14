"""Safe PoC tests: gating + real RCE/SQLi confirmation."""
from __future__ import annotations


def _poc(findings):
    return [f for f in findings if f.module == "safe_poc"]


def test_safe_poc_silent_without_flag(injection_url, scan):
    # Without poc=True the module must do nothing, even when authorized.
    findings = scan(injection_url, ["crawler", "safe_poc"])
    assert _poc(findings) == [], "safe_poc must stay silent without --poc"


def test_safe_poc_proves_rce_and_sqli(injection_url, scan):
    findings = scan(injection_url, ["crawler", "safe_poc"], poc=True)
    poc = _poc(findings)
    titles = " ".join(f.title for f in poc)
    assert "RCE" in titles, f"RCE should be proven, got: {titles}"
    assert "SQL Injection" in titles, f"SQLi should be proven, got: {titles}"
    # everything Safe PoC reports is actually proven
    assert all(f.confidence == "confirmed" for f in poc)
    # evidence must contain real proof, not a guess
    assert any("uid=" in f.evidence for f in poc), "RCE evidence must show id output"
