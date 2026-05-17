"""Self-contained smoke test for the new risk + compliance + reporting code.

Runs without external deps beyond `rich` (already pre-installed). Builds a set
of synthetic findings, runs them through the risk engine, compliance mapper,
bundle builder, and JSON reporter, then prints assertions about the output.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# Ensure local source is importable.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cyberloka.core.compliance import (
    compliance_summary,
    map_finding,
)
from cyberloka.core.config import ScanConfig
from cyberloka.core.finding import Finding, Severity
from cyberloka.core.report_bundle import build_bundle
from cyberloka.core.risk import (
    build_executive_summary,
    grade_from_score,
    overall_score,
    score_finding,
)
from cyberloka.core.target import parse_target
from cyberloka.reporting.json_report import write_json


def make_synthetic_findings() -> list[Finding]:
    return [
        Finding(
            module="sqli",
            title="Kemungkinan SQL Injection (error-based) pada parameter `id`",
            severity=Severity.CRITICAL,
            description="Error SQL muncul setelah injeksi.",
            target="https://example.com/?id=1",
            evidence="you have an error in your sql syntax",
            cwe="CWE-89",
            confidence="firm",
            remediation="Gunakan prepared statements.",
        ),
        Finding(
            module="xss",
            title="Reflected XSS pada parameter `q`",
            severity=Severity.HIGH,
            description="Payload HTML dipantulkan mentah.",
            target="https://example.com/?q=test",
            cwe="CWE-79",
            confidence="firm",
            remediation="Lakukan output encoding.",
        ),
        Finding(
            module="tls",
            title="Sertifikat TLS hampir kedaluwarsa (5 hari)",
            severity=Severity.HIGH,
            description="Cert akan expired.",
            target="example.com:443",
        ),
        Finding(
            module="headers",
            title="Security header hilang: Content-Security-Policy",
            severity=Severity.MEDIUM,
            description="CSP tidak diset.",
            target="https://example.com/",
        ),
        Finding(
            module="cookies",
            title="Cookie `session` kekurangan atribut keamanan: Secure, HttpOnly",
            severity=Severity.MEDIUM,
            description="Cookie tanpa flag.",
            target="https://example.com/",
        ),
        Finding(
            module="headers",
            title="Information disclosure via header `Server`",
            severity=Severity.LOW,
            description="Server: nginx/1.10.3 leaks version.",
            target="https://example.com/",
        ),
        Finding(
            module="fingerprint",
            title="Teknologi terdeteksi: nginx, jQuery 1.7",
            severity=Severity.INFO,
            description="Komponen lama.",
            target="https://example.com/",
        ),
    ]


def assert_eq(label: str, got, want) -> None:
    ok = got == want
    print(f"  [{'OK' if ok else 'FAIL'}] {label}: got={got!r} want={want!r}")
    if not ok:
        sys.exit(1)


def assert_true(label: str, cond: bool, detail: str = "") -> None:
    print(f"  [{'OK' if cond else 'FAIL'}] {label}{(' - ' + detail) if detail else ''}")
    if not cond:
        sys.exit(1)


def test_risk_scores(findings):
    print("== risk scores ==")
    crit = next(f for f in findings if f.module == "sqli")
    high_xss = next(f for f in findings if f.module == "xss")
    info = next(f for f in findings if f.module == "fingerprint")

    s_crit = score_finding(crit)
    s_xss = score_finding(high_xss)
    s_info = score_finding(info)

    assert_true("critical sqli > 9.0", s_crit > 9.0, f"score={s_crit}")
    assert_true("high xss in [6.5, 8.0]", 6.5 <= s_xss <= 8.0, f"score={s_xss}")
    assert_eq("info score is 0", s_info, 0.0)


def test_overall_grade(findings):
    print("== overall grade ==")
    score = overall_score(findings)
    grade = grade_from_score(score)
    print(f"  overall_score={score} grade={grade}")
    # 1 critical + 2 high + 2 medium + 1 low + 1 info -> should be poor
    assert_true("score < 50", score < 50.0)
    assert_true("grade in {D, F}", grade in ("D", "F"))


def test_executive_summary(findings):
    print("== executive summary ==")
    summary = build_executive_summary(findings)
    print(f"  posture: {summary.posture[:80]}...")
    assert_eq("by_severity total matches", sum(summary.by_severity.values()), len(findings))
    assert_eq("total_findings", summary.total_findings, len(findings))
    assert_eq("actionable_findings excludes info", summary.actionable_findings, len(findings) - 1)
    assert_true("top_priorities present", len(summary.top_priorities) > 0)
    # The top priority should be the SQLi (critical, high score).
    top = summary.top_priorities[0]
    assert_eq("top priority module", top["module"], "sqli")


def test_compliance(findings):
    print("== compliance mapping ==")
    sqli = next(f for f in findings if f.module == "sqli")
    m = map_finding(sqli)
    assert_true("SQLi maps to OWASP A03", "A03" in m.owasp_2021)
    assert_true("SQLi maps to PCI 6.2.4", "6.2.4" in m.pci_dss_v4)
    assert_true("SQLi maps to ISO A.8.28", "A.8.28" in m.iso_27001)
    assert_true("SQLi maps to UU PDP", len(m.uu_pdp) > 0)
    assert_true("flat tags non-empty", len(m.as_flat_tags()) > 0)

    summary = compliance_summary(findings)
    print(f"  frameworks present: {sorted(k for k, v in summary.items() if v)}")
    assert_true("OWASP rows non-empty", len(summary["owasp_2021"]) > 0)
    # OWASP A03 should appear because of sqli + xss
    a03 = next((r for r in summary["owasp_2021"] if r["id"] == "A03"), None)
    assert_true("OWASP A03 present", a03 is not None)
    assert_true("OWASP A03 has >=2 findings", a03 and a03["count"] >= 2)


def test_bundle_and_json(findings):
    print("== bundle + json ==")
    target = parse_target("https://example.com/")
    cfg = ScanConfig(target="https://example.com/", mode="full", modules=["sqli", "xss"])
    bundle = build_bundle(target, cfg, findings)

    # round-trip through json
    s = json.dumps(bundle, ensure_ascii=False)
    bundle2 = json.loads(s)
    assert_eq("bundle tool", bundle2["tool"], "cyberloka")
    assert_true("executive_summary present", "executive_summary" in bundle2)
    assert_true("compliance_summary present", "compliance_summary" in bundle2)
    # findings sorted high->low score
    scores = [f["risk_score"] for f in bundle2["findings"]]
    assert_eq("scores descending", scores, sorted(scores, reverse=True))
    # each finding has compliance map
    for f in bundle2["findings"]:
        assert_true(f"finding `{f['module']}` has compliance",
                    "compliance" in f and "compliance_tags" in f)

    # write_json end-to-end
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "scan.json"
        write_json(str(out), target, cfg, findings)
        assert_true("json file written", out.exists())
        loaded = json.loads(out.read_text())
        assert_eq("loaded tool", loaded["tool"], "cyberloka")
        assert_eq("loaded grade matches", loaded["executive_summary"]["grade"], bundle["executive_summary"]["grade"])


def test_console_renderers(findings):
    print("== console renderers (no exception) ==")
    from cyberloka.reporting import console as cr
    cr.render_banner("https://example.com/", "full", ["sqli", "xss", "tls"])
    cr.render_executive_summary(findings)
    cr.render_findings(findings)
    cr.render_compliance_summary(findings)
    cr.render_summary(findings)
    print("  [OK] all console renderers ran")


def main() -> int:
    findings = make_synthetic_findings()
    test_risk_scores(findings)
    test_overall_grade(findings)
    test_executive_summary(findings)
    test_compliance(findings)
    test_bundle_and_json(findings)
    test_console_renderers(findings)
    print("\nAll smoke checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
