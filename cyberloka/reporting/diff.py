"""Diff antara dua report JSON Cyberloka.

Membandingkan dua scan untuk men-track:
- Finding baru muncul (regression).
- Finding yang sudah hilang (fixed).
- Finding yang severity-nya berubah.

Kunci identitas finding (untuk pencocokan stabil):
  (module, title, target_normalised, cwe)

target_normalised: hapus query string supaya scan ulang dengan token URL
acak tetap match.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse


def _normalise_target(t: str) -> str:
    try:
        p = urlparse(t)
        if p.scheme:
            return urlunparse(p._replace(query="", fragment=""))
    except ValueError:
        pass
    return t


def _key(f: dict) -> tuple[str, str, str, str | None]:
    return (
        f.get("module") or "",
        f.get("title") or "",
        _normalise_target(f.get("target") or ""),
        f.get("cwe"),
    )


@dataclass
class DiffResult:
    new: list[dict] = field(default_factory=list)
    fixed: list[dict] = field(default_factory=list)
    changed: list[dict] = field(default_factory=list)
    unchanged_count: int = 0

    def to_dict(self) -> dict:
        return {
            "summary": {
                "new": len(self.new),
                "fixed": len(self.fixed),
                "changed": len(self.changed),
                "unchanged": self.unchanged_count,
            },
            "new": self.new,
            "fixed": self.fixed,
            "changed": self.changed,
        }


def diff_reports(old: dict, new: dict) -> DiffResult:
    res = DiffResult()
    old_findings = old.get("findings") or []
    new_findings = new.get("findings") or []
    old_map: dict[tuple, dict] = {_key(f): f for f in old_findings}
    new_map: dict[tuple, dict] = {_key(f): f for f in new_findings}

    for k, nf in new_map.items():
        if k not in old_map:
            res.new.append(nf)
        else:
            of = old_map[k]
            if (of.get("severity") != nf.get("severity")) or (
                of.get("evidence") != nf.get("evidence")
            ):
                res.changed.append(
                    {"old": of, "new": nf}
                )
            else:
                res.unchanged_count += 1

    for k, of in old_map.items():
        if k not in new_map:
            res.fixed.append(of)

    return res


def diff_files(old_path: str, new_path: str) -> DiffResult:
    with open(old_path, encoding="utf-8") as fp:
        old = json.load(fp)
    with open(new_path, encoding="utf-8") as fp:
        new = json.load(fp)
    return diff_reports(old, new)


def render_text(diff: DiffResult) -> str:
    lines: list[str] = []
    s = diff.to_dict()["summary"]
    lines.append(
        f"Diff summary: NEW={s['new']} FIXED={s['fixed']} CHANGED={s['changed']} UNCHANGED={s['unchanged']}"
    )
    if diff.new:
        lines.append("\n=== NEW ===")
        for f in diff.new:
            lines.append(f"  + [{f.get('severity','?').upper()}] {f.get('module')}: {f.get('title')}")
            lines.append(f"      target: {f.get('target')}")
    if diff.fixed:
        lines.append("\n=== FIXED ===")
        for f in diff.fixed:
            lines.append(f"  - [{f.get('severity','?').upper()}] {f.get('module')}: {f.get('title')}")
            lines.append(f"      target: {f.get('target')}")
    if diff.changed:
        lines.append("\n=== CHANGED ===")
        for c in diff.changed:
            o, n = c["old"], c["new"]
            lines.append(
                f"  ~ {o.get('module')}: {o.get('title')}\n"
                f"      severity: {o.get('severity')} -> {n.get('severity')}"
            )
    return "\n".join(lines)
