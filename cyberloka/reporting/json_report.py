"""JSON report exporter."""
from __future__ import annotations

import json
from pathlib import Path

from cyberloka.core import Finding, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.report_bundle import build_bundle


def write_json(
    path: str, target: Target, config: ScanConfig, findings: list[Finding]
) -> None:
    bundle = build_bundle(target, config, findings)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(bundle, fp, indent=2, ensure_ascii=False)
