"""Pure-Python helpers used by the dashboard.

Kept Flask-free so unit tests can exercise them without the optional
dashboard dependency.
"""
from __future__ import annotations

from typing import Any


def filter_findings(
    findings: list[dict[str, Any]],
    severity: str | None,
    module: str | None,
    framework: str | None,
    clause: str | None,
    q: str | None,
) -> list[dict[str, Any]]:
    """Apply UI filters to a list of finding dicts."""
    out = findings
    if severity:
        sevs = {s.strip().lower() for s in severity.split(",") if s.strip()}
        out = [f for f in out if f.get("severity") in sevs]
    if module:
        mods = {m.strip().lower() for m in module.split(",") if m.strip()}
        out = [f for f in out if f.get("module") in mods]
    if framework and clause:
        out = [
            f
            for f in out
            if any(
                c.get("id") == clause
                for c in f.get("compliance", {}).get(framework, [])
            )
        ]
    if q:
        ql = q.lower().strip()
        out = [
            f
            for f in out
            if ql in (f.get("title", "") or "").lower()
            or ql in (f.get("description", "") or "").lower()
            or ql in (f.get("module", "") or "").lower()
            or ql in (f.get("evidence", "") or "").lower()
        ]
    return out


def diff_findings(
    a: list[dict[str, Any]], b: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Side-by-side diff between two scans, keyed on (module, title)."""
    def key(f: dict[str, Any]) -> tuple[str, str]:
        return (f.get("module", ""), f.get("title", ""))

    a_map = {key(f): f for f in a}
    b_map = {key(f): f for f in b}
    a_keys = set(a_map)
    b_keys = set(b_map)
    return {
        "resolved": [a_map[k] for k in sorted(a_keys - b_keys)],
        "new":      [b_map[k] for k in sorted(b_keys - a_keys)],
        "unchanged":[b_map[k] for k in sorted(a_keys & b_keys)],
    }
