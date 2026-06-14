"""SARIF 2.1.0 export tests: valid envelope, one rule per module, severity mapping."""
from __future__ import annotations

import json

from cyberloka.core import Finding, Severity
from cyberloka.core.config import ScanConfig
from cyberloka.core.target import parse_target
from cyberloka.reporting.sarif import build_sarif, write_sarif


def _findings() -> list[Finding]:
    return [
        Finding(
            module="sqli", title="SQL injection terdeteksi",
            severity=Severity.CRITICAL, description="error-based SQLi",
            target="http://t/item?id=1", evidence="SQL syntax error",
            cwe="CWE-89", confidence="confirmed",
        ),
        Finding(
            module="headers", title="Missing security header",
            severity=Severity.LOW, description="no HSTS",
            target="http://t/", cwe="CWE-693", confidence="firm",
        ),
        Finding(
            module="sqli", title="SQL injection kedua",
            severity=Severity.HIGH, description="boolean-based",
            target="http://t/item?id=2", cwe="CWE-89", confidence="tentative",
        ),
    ]


def test_sarif_envelope_and_rules():
    cfg = ScanConfig(target="http://t/")
    doc = build_sarif(parse_target("http://t/"), cfg, _findings())
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "cyberloka"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids == {"cyberloka/sqli", "cyberloka/headers"}, "one rule per module"
    assert len(run["results"]) == 3, "one result per finding"


def test_sarif_level_and_security_severity():
    cfg = ScanConfig(target="http://t/")
    run = build_sarif(parse_target("http://t/"), cfg, _findings())["runs"][0]
    by_target = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: r
                 for r in run["results"]}
    assert by_target["http://t/item?id=1"]["level"] == "error"   # critical
    assert by_target["http://t/"]["level"] == "note"             # low
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "cyberloka/sqli")
    score = float(rule["properties"]["security-severity"])
    assert 0.0 <= score <= 10.0


def test_sarif_written_to_disk(tmp_path):
    cfg = ScanConfig(target="http://t/")
    out = tmp_path / "out.sarif"
    write_sarif(str(out), parse_target("http://t/"), cfg, _findings())
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["runs"][0]["results"][0]["ruleId"].startswith("cyberloka/")
    assert loaded["runs"][0]["results"][0]["partialFingerprints"]


def test_sarif_empty_findings():
    cfg = ScanConfig(target="http://t/")
    doc = build_sarif(parse_target("http://t/"), cfg, [])
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
