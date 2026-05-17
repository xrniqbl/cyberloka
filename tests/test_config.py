from cyberloka.core.config import ScanConfig


def test_passive_mode_resolves_passive_modules():
    cfg = ScanConfig(target="https://x")
    mods = cfg.resolve_modules()
    assert "headers" in mods and "tls" in mods
    assert "sqli" not in mods
    assert "crawler" not in mods


def test_active_mode_includes_passive_and_active():
    cfg = ScanConfig(target="https://x", mode="active")
    mods = cfg.resolve_modules()
    for m in ("headers", "sqli", "xss", "ssrf", "jwt", "xxe", "ssti", "nosqli", "graphql", "websocket"):
        assert m in mods, f"{m} should be in active mode"


def test_full_mode_includes_recon():
    cfg = ScanConfig(target="https://x", mode="full")
    mods = cfg.resolve_modules()
    for m in ("dns", "whois", "ports", "subdomains", "fingerprint", "crawler", "openapi"):
        assert m in mods


def test_explicit_modules_override_mode():
    cfg = ScanConfig(target="https://x", mode="full", modules=["headers", "tls"])
    assert cfg.resolve_modules() == ["headers", "tls"]


def test_crawl_flag_adds_crawler_to_passive():
    cfg = ScanConfig(target="https://x", crawl=True)
    mods = cfg.resolve_modules()
    assert mods[0] == "crawler"
