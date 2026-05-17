from cyberloka.core.finding import Finding, Severity


def test_severity_order_critical_first():
    assert Severity.CRITICAL.order < Severity.HIGH.order
    assert Severity.HIGH.order < Severity.MEDIUM.order
    assert Severity.MEDIUM.order < Severity.LOW.order
    assert Severity.LOW.order < Severity.INFO.order


def test_finding_to_dict_serialises_severity_as_string():
    f = Finding(
        module="x",
        title="t",
        severity=Severity.HIGH,
        description="d",
        target="https://example.com",
    )
    d = f.to_dict()
    assert d["severity"] == "high"
    assert d["module"] == "x"
    assert d["target"] == "https://example.com"
    assert "detected_at" in d
