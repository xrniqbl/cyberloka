"""OTP / 2FA endpoint posture (rate-limit, length, reuse)."""
from __future__ import annotations

import re
import secrets
import time

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

OTP_HINTS = re.compile(r"otp|2fa|verify|verifikasi|kode", re.I)
OTP_FIELDS = re.compile(r"otp|code|kode|token|verify|pin", re.I)


def _otp_forms(config: ScanConfig) -> list[dict]:
    state = get_state(config)
    if not state:
        return []
    out = []
    for f in state.forms:
        action_low = (f.get("action") or "").lower()
        names = " ".join(i.get("name", "") for i in f["inputs"]).lower()
        if OTP_HINTS.search(action_low) or OTP_FIELDS.search(names):
            out.append(f)
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        forms = _otp_forms(config)
        for form in forms[:2]:
            otp_field = next(
                (i["name"] for i in form["inputs"]
                 if OTP_FIELDS.search(i.get("name", "") or "")),
                None,
            )
            if not otp_field:
                continue
            base = {i["name"]: (i.get("value") or "x") for i in form["inputs"]
                    if i.get("type") not in ("submit", "button")}
            method = (form.get("method") or "post").lower()
            action = form["action"]

            # Rate-limit probe: 8 percobaan OTP cepat berurutan
            statuses = []
            t0 = time.monotonic()
            for _ in range(8):
                wrong = secrets.token_hex(3)[:6]
                r = (client.post(action, data={**base, otp_field: wrong})
                     if method == "post"
                     else client.get(action, params={**base, otp_field: wrong}))
                if r is None:
                    break
                statuses.append(r.status_code)
            elapsed = time.monotonic() - t0
            if statuses and not any(s == 429 for s in statuses) and statuses.count(200) >= 5:
                findings.append(Finding(
                    module="otp_check",
                    title="Endpoint OTP tidak menerapkan rate-limit yang terdeteksi",
                    severity=Severity.HIGH,
                    description=("8 percobaan OTP salah berturut-turut tidak memicu 429. "
                                 "Attacker dapat brute-force OTP 4-6 digit dengan cepat."),
                    target=action,
                    evidence=f"statuses={statuses}, elapsed={elapsed:.1f}s",
                    cwe="CWE-307", confidence="tentative",
                    remediation=("Batasi 5 percobaan / 15 menit per akun + per IP. "
                                 "Invalidate OTP setelah N kali salah, kirim alert."),
                ))

            # Probe panjang OTP (pendek = brute-friendly)
            r1 = (client.post(action, data={**base, otp_field: "1234"})
                  if method == "post"
                  else client.get(action, params={**base, otp_field: "1234"}))
            r2 = (client.post(action, data={**base, otp_field: "1"*12})
                  if method == "post"
                  else client.get(action, params={**base, otp_field: "1"*12}))
            if r1 is not None and r2 is not None:
                b1 = (r1.text or "").lower()
                if any(k in b1 for k in ("invalid otp", "wrong code", "kode salah",
                                          "kode tidak valid", "incorrect otp")):
                    # Indikasi accept 4-digit input — banyak app pakai 4 digit (10000 combo)
                    findings.append(Finding(
                        module="otp_check",
                        title="OTP tampaknya menerima 4-digit (ruang search ~10k)",
                        severity=Severity.MEDIUM,
                        description=("Form OTP merespons normal pada input 4 digit. "
                                     "OTP 4 digit + tanpa rate-limit kuat = brute-force "
                                     "mudah."),
                        target=action,
                        evidence="response berisi pesan 'invalid OTP' untuk input 4-digit",
                        cwe="CWE-310", confidence="tentative",
                        remediation=("Gunakan OTP 6 digit (≥10⁶ kombinasi), expired ≤5 menit, "
                                     "satu kali pakai, dan rate-limit ketat."),
                    ))
    finally:
        client.close()
    return findings
