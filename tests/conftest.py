"""Shared pytest fixtures: spin up the vulnerable Flask fixtures on a free port
and provide a helper to run cyberloka modules against them.
"""
from __future__ import annotations

import threading
from collections.abc import Callable, Iterator

import pytest
from werkzeug.serving import make_server

from cyberloka.core import Finding
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.scanner import run_scan
from tests.fixtures.injection_app import create_app as create_injection_app
from tests.fixtures.wcd_app import create_app as create_wcd_app


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
def injection_url() -> Iterator[str]:
    with _Server(create_injection_app()) as base:
        yield base


@pytest.fixture()
def wcd_url() -> Iterator[str]:
    with _Server(create_wcd_app()) as base:
        yield base


@pytest.fixture()
def scan() -> Callable[..., list[Finding]]:
    """Run the real orchestrator for the given modules and return findings."""
    def _scan(base_url: str, modules: list[str], **cfg_kwargs) -> list[Finding]:
        cfg = ScanConfig(
            target=base_url,
            modules=list(modules),
            authorized=True,
            rate_limit=0.0,   # no throttle in tests
            timeout=8.0,
            **cfg_kwargs,
        )
        return run_scan(parse_target(base_url), cfg)
    return _scan
