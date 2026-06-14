"""SARIF 2.1.0 report exporter (GitHub code-scanning compatible).

Emits findings as a SARIF log so results can be uploaded to GitHub Advanced
Security (code scanning) or any SARIF-aware viewer. One rule per module,
one result per finding. Severity is exposed via the `security-severity`
property (0-10) that GitHub uses to rank alerts.
"""
from __future__ import annotations

import hashlib
import json

from cyberloka import __version__
from cyberloka.core import Finding, Target
from cyberloka.core.config import ScanConfig

TOOL_URI = "https://github.com/xrniqbl/cyberloka"

# SARIF result.level by severity bucket.
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _security_severity(finding: Finding) -> str:
    """Map the 1-100 risk score onto SARIF's 0.0-10.0 scale."""
    return f"{round(finding.risk_score / 10.0, 1)}"


def _rule_id(module: str) -> str:
    return f"cyberloka/{module}"


def _fingerprint(finding: Finding) -> str:
    raw = f"{finding.module}|{finding.target}|{finding.title}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _build_rules(findings: list[Finding]) -> list[dict]:
    rules: dict[str, dict] = {}
    for f in findings:
        if f.module in rules:
            continue
        tags = ["security"]
        if f.cwe:
            tags.append(f.cwe.lower())
        if f.owasp_category:
            tags.append(f.owasp_category)
        rule = {
            "id": _rule_id(f.module),
            "name": f.module,
            "shortDescription": {"text": f.title[:120] or f.module},
            "fullDescription": {"text": f.description or f.title or f.module},
            "defaultConfiguration": {"level": _LEVEL.get(f.severity.value, "warning")},
            "properties": {
                "tags": tags,
                "security-severity": _security_severity(f),
            },
        }
        if f.cwe:
            rule["properties"]["cwe"] = f.cwe
        if f.remediation:
            rule["help"] = {"text": f.remediation}
        if f.references:
            rule["helpUri"] = f.references[0]
        rules[f.module] = rule
    return list(rules.values())


def _build_result(finding: Finding) -> dict:
    msg_parts = [finding.title]
    if finding.evidence:
        msg_parts.append(f"Evidence: {finding.evidence}")
    result = {
        "ruleId": _rule_id(finding.module),
        "level": _LEVEL.get(finding.severity.value, "warning"),
        "message": {"text": "\n".join(msg_parts)},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.target or "unknown"}
            }
        }],
        "partialFingerprints": {"cyberloka/v1": _fingerprint(finding)},
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "risk_score": finding.risk_score,
        },
    }
    if finding.cwe:
        result["properties"]["cwe"] = finding.cwe
    return result


def build_sarif(target: Target, config: ScanConfig, findings: list[Finding]) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cyberloka",
                    "version": __version__,
                    "informationUri": TOOL_URI,
                    "rules": _build_rules(findings),
                }
            },
            "results": [_build_result(f) for f in findings],
        }],
    }


def write_sarif(path: str, target: Target, config: ScanConfig,
                findings: list[Finding]) -> None:
    data = build_sarif(target, config, findings)
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, ensure_ascii=False)
