"""Rate-limit bypass via X-Forwarded-For variation."""
from __future__ import annotations

import secrets

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    login_url = None
    if s:
        for f in s.forms:
            if any((i.get("type") or "").lower() == "password" for i in f["inputs"]):
                login_url = f.get("action"); break
    if not login_url:
        return findings

    client = HttpClient(config)
    try:
        # Burst 30 wrong logins from same IP — should hit rate limit
        statuses_same: list[int] = []
        for _ in range(30):
            r = client.post(login_url, data={"username": "x", "password": "wrong" + secrets.token_hex(2)})
            if r is None:
                break
            statuses_same.append(r.status_code)
            if r.status_code == 429:
                break
        if 429 not in statuses_same:
            # No rate limit at all
            return findings  # api_auth module already handles this

        # Rate limit detected. Now try with rotated X-Forwarded-For
        statuses_rotated: list[int] = []
        for i in range(30):
            ip = f"10.0.{i // 256}.{i % 256}"
            r = client.post(login_url,
                            headers={"X-Forwarded-For": ip, "X-Real-IP": ip,
                                     "X-Originating-IP": ip},
                            data={"username": "x", "password": "wrong" + secrets.token_hex(2)})
            if r is None:
                break
            statuses_rotated.append(r.status_code)
        # Kalau dengan XFF tidak pernah kena 429 = bypass berhasil
        if 429 not in statuses_rotated:
            findings.append(Finding(
                module="rate_limit_bypass", target=login_url,
                title="Rate-limit dapat di-bypass via X-Forwarded-For rotation",
                severity=Severity.HIGH,
                description=("Server membatasi rate per-IP, tapi pakai header `X-Forwarded-For` "
                             "dari klien sebagai source IP. Attacker rotasi XFF = tetap brute-force "
                             "tanpa kena rate limit."),
                evidence=f"same-IP triggered 429 in {len(statuses_same)} req; "
                         f"with rotated XFF: {len(statuses_rotated)} req tanpa 429",
                cwe="CWE-693",
                remediation=("Pakai source IP dari TCP layer (REMOTE_ADDR), bukan dari header. "
                             "Untuk app di balik reverse-proxy, hanya trust XFF dari proxy yang "
                             "diketahui (whitelist IP proxy)."),
            ))
    finally:
        client.close()
    return findings
