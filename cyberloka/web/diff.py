"""Compute finding-level diff between two scans."""
from __future__ import annotations


def _key(f: dict) -> tuple[str, str, str]:
    """Identity tuple used to compare findings across scans."""
    return (f.get("module") or "", f.get("title") or "", f.get("target") or "")


def diff_scans(prev_findings: list[dict], curr_findings: list[dict]) -> dict:
    """Return added / fixed / unchanged buckets of findings."""
    prev_map = {_key(f): f for f in prev_findings}
    curr_map = {_key(f): f for f in curr_findings}
    added = [f for k, f in curr_map.items() if k not in prev_map]
    fixed = [f for k, f in prev_map.items() if k not in curr_map]
    unchanged = [f for k, f in curr_map.items() if k in prev_map]
    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sort_key = lambda f: (sev_order.get(f.get("severity", "info"), 4), f.get("module", ""))  # noqa: E731
    return {
        "added": sorted(added, key=sort_key),
        "fixed": sorted(fixed, key=sort_key),
        "unchanged": sorted(unchanged, key=sort_key),
        "summary": {
            "added": len(added),
            "fixed": len(fixed),
            "unchanged": len(unchanged),
        },
    }
