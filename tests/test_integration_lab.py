"""Integration tests that hit the local Docker lab.

Aktifkan dengan:
    cd lab && docker compose up -d
    CYBERLOKA_LAB=1 pytest tests/test_integration_lab.py -v
"""
from __future__ import annotations

import pytest

from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target


@pytest.mark.integration
def test_juiceshop_passive_scan_returns_findings(juiceshop_url):
    from cyberloka.scanner import run_scan

    target = parse_target(juiceshop_url)
    cfg = ScanConfig(
        target=juiceshop_url,
        mode="passive",
        modules=["headers", "cookies", "methods", "robots"],
        rate_limit=20,
        timeout=8,
        authorized=True,
    )
    findings = run_scan(target, cfg)
    # Juice Shop sengaja rentan → minimal beberapa finding harus muncul
    assert len(findings) >= 1
    modules = {f.module for f in findings}
    assert "headers" in modules


@pytest.mark.integration
def test_juiceshop_crawler_finds_endpoints(juiceshop_url):
    from cyberloka.recon.crawler import crawl

    target = parse_target(juiceshop_url)
    cfg = ScanConfig(target=juiceshop_url, rate_limit=20, timeout=8, authorized=True)
    res = crawl(target, cfg, max_pages=15, max_depth=2)
    assert len(res.visited) >= 1
