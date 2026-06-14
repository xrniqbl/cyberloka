"""Unit test for the --min-confidence filter."""
from cyberloka.cli import filter_by_confidence
from cyberloka.core import Finding, Severity


def _f(conf: str) -> Finding:
    return Finding(module="m", title="t", severity=Severity.HIGH,
                   description="d", target="http://x", confidence=conf)


def test_filter_levels():
    findings = [_f("tentative"), _f("firm"), _f("confirmed")]
    assert len(filter_by_confidence(findings, "tentative")) == 3
    assert {f.confidence for f in filter_by_confidence(findings, "firm")} == {"firm", "confirmed"}
    assert [f.confidence for f in filter_by_confidence(findings, "confirmed")] == ["confirmed"]


def test_unknown_confidence_treated_as_firm():
    findings = [_f("weird")]
    assert len(filter_by_confidence(findings, "firm")) == 1     # weird -> firm rank passes
    assert len(filter_by_confidence(findings, "confirmed")) == 0


def test_default_shows_all():
    findings = [_f("tentative"), _f("firm")]
    assert len(filter_by_confidence(findings, "tentative")) == 2
