from cyberloka.core.config import ScanConfig


def test_passive_mode_includes_recon_ringan_dan_passive_checks():
    cfg = ScanConfig(target="https://x")
    mods = cfg.resolve_modules()
    # passive sekarang juga punya recon ringan
    assert "headers" in mods and "tls" in mods
    assert "dns" in mods and "whois" in mods and "fingerprint" in mods
    # tapi tidak melakukan port scan / subdomain bruteforce
    assert "ports" not in mods
    assert "subdomains" not in mods
    # juga tidak active checks
    assert "sqli" not in mods


def test_active_mode_includes_ports_subdomains_and_active_checks():
    cfg = ScanConfig(target="https://x", mode="active")
    mods = cfg.resolve_modules()
    for m in (
        "headers", "sqli", "xss", "ssrf", "jwt", "xxe", "ssti",
        "nosqli", "graphql", "websocket",
        # ditambahkan: ports & subdomains supaya laporan kaya
        "ports", "subdomains", "openapi", "dns", "whois", "fingerprint",
        # detector lebih dalam
        "payment", "idor", "host_header", "mass_assign", "hpp",
    ):
        assert m in mods, f"{m} should be in active mode"


def test_full_mode_includes_everything_plus_crawler():
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
    assert "crawler" in mods


def test_no_duplicate_modules():
    cfg = ScanConfig(target="https://x", mode="active", crawl=True)
    mods = cfg.resolve_modules()
    assert len(mods) == len(set(mods))
