"""Timing-attack probe on login/reset endpoints — strict-validation v0.10.4.

Sebelumnya: 5 sampel per grup + threshold 150ms. Variasi network alami
sering melewati threshold itu, jadi banyak false positive.

Sekarang: 10 sampel interleaved + ``detect_timing_oracle`` (median +
pooled stdev + z-score >= 3.0 + delta median >= 200 ms). Signal yang
lolos saringan ini sangat tipis kemungkinan dari jitter.
"""
from __future__ import annotations

import secrets
import time

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
    detect_timing_oracle,
)
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
    user_field = next(
        (i["name"] for i in form["inputs"]
         if (i.get("name") or "").lower() in ("username", "email", "user")),
        None,
    )
    pass_field = next(
        (i["name"] for i in form["inputs"]
         if (i.get("type") or "").lower() == "password"),
        None,
    )
    if not (user_field and pass_field):
        return findings

    client = HttpClient(config)
    try:
        invalid_times: list[float] = []
        common_times: list[float] = []
        # Interleaved sampling untuk meredam network drift.
        for _ in range(10):
            tag = secrets.token_hex(4)
            t0 = time.monotonic()
            client.post(
                form["action"],
                data={user_field: f"nopex_{tag}@invalid", pass_field: "wrong"},
            )
            invalid_times.append(time.monotonic() - t0)

            t0 = time.monotonic()
            client.post(
                form["action"],
                data={user_field: "admin",
                      pass_field: f"wrong{secrets.token_hex(2)}"},
            )
            common_times.append(time.monotonic() - t0)

        confirmed, delta_ms, t_score = detect_timing_oracle(
            invalid_times, common_times,
            min_delta_ms=200.0, min_samples=10,
        )
        if not confirmed:
            return findings

        med_inv_ms = sorted(invalid_times)[len(invalid_times) // 2] * 1000
        med_com_ms = sorted(common_times)[len(common_times) // 2] * 1000
        proof = ValidationProof(
            method="multi-sample+pooled-stdev",
            confirmed=True,
            steps=[
                "Kumpulkan 10 sampel waktu untuk user invalid + 10 sampel untuk user umum.",
                f"Median user invalid : {med_inv_ms:.0f} ms",
                f"Median user umum    : {med_com_ms:.0f} ms",
                f"|Δmedian| = {abs(delta_ms):.0f} ms (threshold 200 ms).",
                f"z-score (pooled stdev) = {t_score:.2f} (threshold 3.0).",
            ],
            samples=[
                "invalid: " + ", ".join(f"{t*1000:.0f}ms" for t in invalid_times),
                "common : " + ", ".join(f"{t*1000:.0f}ms" for t in common_times),
            ],
        )
        findings.append(Finding(
            module="timing_attack", target=form["action"],
            title=f"Timing oracle terkonfirmasi (Δ={delta_ms:.0f}ms, z={t_score:.1f})",
            severity=Severity.MEDIUM,
            description=(
                "Waktu respons login berbeda signifikan untuk user yang ada vs "
                "tidak ada (delta median > 200 ms, z-score > 3). Attacker dapat "
                "enumerasi akun valid lewat timing measurement, walaupun server "
                "memberi pesan generik."
            ),
            evidence=f"|delta|={abs(delta_ms):.0f}ms, z={t_score:.2f}",
            cwe="CWE-208",
            confidence="confirmed",
            urls=[form["action"]],
            remediation=(
                "Jalankan password hashing constant-time bahkan saat user "
                "tidak ada (mis. dummy bcrypt verify), atau pakai response "
                "generic dengan delay tetap untuk login & reset."
            ),
            extra=build_extra(proof=proof),
        ))
    finally:
        client.close()
    return findings
