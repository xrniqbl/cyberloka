"""OOB collaborator tests: blind SSRF confirmed on vulnerable app, silent on safe.

Spins up a real cyberloka collaborator server plus a vulnerable fetch endpoint,
seeds crawler state with the param URL, and runs the oob_probe module directly.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator

import pytest
from werkzeug.serving import make_server

from cyberloka.active import oob_probe
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.oob_server import app as collab_app
from cyberloka.recon.crawler import CrawlState, _set_state
from tests.fixtures.oob_app import create_safe_app, create_vuln_app


class _Server:
    def __init__(self, app):
        self.srv = make_server("127.0.0.1", 0, app, threaded=True)
        self.port = self.srv.server_port
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)

    def __enter__(self) -> str:
        self.thread.start()
        return f"http://127.0.0.1:{self.port}"

    def __exit__(self, *exc) -> None:
        self.srv.shutdown()
        self.thread.join(timeout=5)


@pytest.fixture()
def collaborator() -> Iterator[str]:
    with _Server(collab_app) as base:
        yield base


def _cfg(base_url: str, oob_url: str) -> ScanConfig:
    cfg = ScanConfig(
        target=base_url, mode="active", authorized=True,
        oob_url=oob_url, rate_limit=0.0, timeout=8.0,
    )
    state = CrawlState()
    state.param_urls = [f"{base_url}/fetch?url=http://placeholder/"]
    _set_state(cfg, state)
    return cfg


def test_oob_confirms_blind_ssrf(collaborator):
    with _Server(create_vuln_app()) as base:
        findings = oob_probe.run(parse_target(base), _cfg(base, collaborator))
    assert findings, "blind SSRF must be confirmed via OOB callback"
    assert all(f.confidence == "confirmed" for f in findings)
    assert findings[0].cwe == "CWE-918"


def test_oob_silent_on_safe_app(collaborator):
    with _Server(create_safe_app()) as base:
        findings = oob_probe.run(parse_target(base), _cfg(base, collaborator))
    assert findings == [], "no outbound fetch => no false positive"


def test_oob_skipped_without_oob_url():
    with _Server(create_vuln_app()) as base:
        cfg = ScanConfig(target=base, mode="active", authorized=True, rate_limit=0.0)
        state = CrawlState()
        state.param_urls = [f"{base}/fetch?url=http://placeholder/"]
        _set_state(cfg, state)
        assert oob_probe.run(parse_target(base), cfg) == []


def test_oob_skipped_without_authorization(collaborator):
    with _Server(create_vuln_app()) as base:
        cfg = ScanConfig(target=base, mode="active", authorized=False,
                         oob_url=collaborator, rate_limit=0.0)
        state = CrawlState()
        state.param_urls = [f"{base}/fetch?url=http://placeholder/"]
        _set_state(cfg, state)
        assert oob_probe.run(parse_target(base), cfg) == []
