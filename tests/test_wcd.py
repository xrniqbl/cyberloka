"""Web Cache Deception tests: confirmed on vulnerable endpoint, silent on safe."""
from __future__ import annotations


def test_wcd_confirmed_on_vulnerable_account(wcd_url, scan):
    findings = scan(wcd_url, ["web_cache_deception"], cookies={"session": "victim"})
    wcd = [f for f in findings if f.module == "web_cache_deception"]
    assert wcd, "WCD on /account should be detected"
    assert any(f.confidence == "confirmed" for f in wcd), "anon leak must be confirmed"
    assert all("/profile" not in f.target for f in wcd), "safe /profile must not be flagged"


def test_wcd_silent_without_session(wcd_url, scan):
    # No auth cookie => no per-user marker => cannot prove WCD => silent.
    findings = scan(wcd_url, ["web_cache_deception"])
    assert [f for f in findings if f.module == "web_cache_deception"] == []
