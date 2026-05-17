"""Pytest fixtures."""
from __future__ import annotations

import os
import socket
import time

import pytest

LAB_TARGETS = {
    "juiceshop": ("127.0.0.1", 3000),
    "dvwa": ("127.0.0.1", 8080),
    "vampi": ("127.0.0.1", 5001),
}


def _is_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def pytest_collection_modifyitems(config, items):
    """Skip tests bertanda 'integration' bila CYBERLOKA_LAB tidak diset
    atau service lab tidak hidup."""
    run_int = os.environ.get("CYBERLOKA_LAB") == "1"
    skip_int = pytest.mark.skip(reason="set CYBERLOKA_LAB=1 dan jalankan lab/docker-compose untuk integration tests")
    for item in items:
        if "integration" in item.keywords and not run_int:
            item.add_marker(skip_int)


@pytest.fixture(scope="session")
def juiceshop_url() -> str:
    host, port = LAB_TARGETS["juiceshop"]
    if not _is_open(host, port):
        pytest.skip("Juice Shop tidak running di 127.0.0.1:3000")
    # tunggu siap
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if _is_open(host, port):
            return f"http://{host}:{port}"
        time.sleep(1)
    pytest.skip("Juice Shop timeout")
    return ""
