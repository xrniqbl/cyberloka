from cyberloka.reporting.diff import diff_reports


def _f(module, title, severity="medium", target="https://x/", cwe=None):
    return {
        "module": module,
        "title": title,
        "severity": severity,
        "target": target,
        "cwe": cwe,
        "evidence": "",
    }


def test_diff_detects_new_finding():
    old = {"findings": [_f("headers", "missing CSP")]}
    new = {"findings": [_f("headers", "missing CSP"), _f("xss", "reflected")]}
    d = diff_reports(old, new)
    assert len(d.new) == 1
    assert d.new[0]["module"] == "xss"
    assert d.fixed == []


def test_diff_detects_fixed_finding():
    old = {"findings": [_f("xss", "reflected")]}
    new = {"findings": []}
    d = diff_reports(old, new)
    assert len(d.fixed) == 1
    assert d.new == []


def test_diff_detects_severity_change():
    old = {"findings": [_f("xss", "reflected", "medium")]}
    new = {"findings": [_f("xss", "reflected", "high")]}
    d = diff_reports(old, new)
    assert len(d.changed) == 1
    assert d.changed[0]["old"]["severity"] == "medium"
    assert d.changed[0]["new"]["severity"] == "high"


def test_diff_target_query_string_normalised():
    old = {"findings": [_f("xss", "reflected", target="https://x/path?token=1")]}
    new = {"findings": [_f("xss", "reflected", target="https://x/path?token=2")]}
    d = diff_reports(old, new)
    assert d.unchanged_count == 1
    assert not d.new and not d.fixed
