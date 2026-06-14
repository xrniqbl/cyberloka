"""Smoke test: every registered module imports and exposes a callable run().

Cheapest, highest-value regression guard — a syntax/import error in any of the
100+ modules fails CI immediately.
"""
from __future__ import annotations

import importlib

import pytest

from cyberloka.scanner import MODULE_MAP


@pytest.mark.parametrize("name,path", sorted(MODULE_MAP.items()))
def test_module_imports_and_has_run(name: str, path: str) -> None:
    mod = importlib.import_module(path)
    assert callable(getattr(mod, "run", None)), f"{name} ({path}) missing run()"


def test_module_map_matches_active_passive_lists() -> None:
    from cyberloka.core.config import ScanConfig
    for m in ScanConfig.ACTIVE_MODULES + ScanConfig.PASSIVE_MODULES + ScanConfig.RECON_MODULES:
        assert m in MODULE_MAP, f"{m} listed in config but missing from MODULE_MAP"
