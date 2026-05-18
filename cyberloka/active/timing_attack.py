"""Timing-attack probe on login/reset endpoints."""
from __future__ import annotations

import secrets
import statistics
import time

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state


def _login_form(config: ScanConfig) -> dict | None:
    s = get_state(config)
    if not s:
        return None
    for f in s.forms:
        if any((i.get("type") or "").lower() == "password" for i in f["inputs"]):
            return f
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    form = _login_form(config)
    if not form:
        return findings
    user_field = next((i["name"] for i in form["inputs"]
                       if (i.get("name") or "").lower() in ("username", "email", "user")), None)
    pass_field = next((i["name"] for i in form["inputs"]
                       if (i.get("type") or "").lower() == "password"), None)
    if not (user_field and pass_field):
        return findings

    client = HttpClient(config)
    try:
        # 5 invalid users vs 5 common users
        invalid_times = []
        common_times = []
        for _ in range(5):
            tag = secrets.token_hex(4)
            t0 = time.monotonic()
            client.post(form["action"], data={user_field: f"nopex_{tag}@invalid", pass_field: "wrong"})
            invalid_times.append(time.monotonic() - t0)
        for _ in range(5):
            t0 = time.monotonic()
            client.post(form["action"], data={user_field: "admin", pass_field: f"wrong{secrets.token_hex(2)}"})
            common_times.append(time.monotonic() - t0)
        if not invalid_times or not common_times:
            return findings
        m_inv = statistics.mean(invalid_times)
        m_com = statistics.mean(common_times)
        delta = abs(m_inv - m_com)
        if delta > 0.150:
            findings.append(Finding(
                module="timing_attack", target=form["action"],
                title=f"Beda timing login signifikan ({delta*1000:.0f}ms)",
                severity=Severity.MEDIUM,
                description=("Waktu respons login berbeda untuk user yang ada vs tidak ada. "
                             "Attacker dapat enumerasi akun valid lewat timing measurement."),
                evidence=f"invalid avg={m_inv*1000:.0f}ms, common avg={m_com*1000:.0f}ms",
                cwe="CWE-208", confidence="tentative",
                remediation=("Jalankan password hashing constant-time bahkan saat user tidak ada "
                             "(dummy bcrypt verify), atau pakai tanggapan generic dengan delay tetap."),
            ))
    finally:
        client.close()
    return findings
