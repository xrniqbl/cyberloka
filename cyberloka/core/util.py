"""Utility helpers."""
from __future__ import annotations

import importlib.resources as resources
from pathlib import Path


def load_data_lines(filename: str) -> list[str]:
    """Load a wordlist/data file from the package data directory."""
    pkg_root = Path(__file__).resolve().parent.parent.parent
    candidate = pkg_root / "data" / filename
    if candidate.exists():
        return [
            line.strip()
            for line in candidate.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
    # fallback to package data
    try:
        text = resources.files("cyberloka").joinpath(f"data/{filename}").read_text(
            encoding="utf-8"
        )
        return [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
    except (FileNotFoundError, ModuleNotFoundError):
        return []


def truncate(s: str, n: int = 200) -> str:
    s = s.replace("\n", " ").replace("\r", " ")
    return s if len(s) <= n else s[:n] + "..."
