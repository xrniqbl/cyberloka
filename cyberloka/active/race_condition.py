"""Race-condition smoke test on voucher/withdraw/claim endpoints."""
from __future__ import annotations

import threading

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

CRITICAL_HINTS = ("redeem", "claim", "withdraw", "tarik", "saldo",
                  "voucher/apply", "checkout/confirm", "kupon", "promo/redeem")
SUCCESS = ("success", "berhasil", "applied", "ok", "diterapkan", "claimed")


def _critical_endpoints(target: Target, config: ScanConfig) -> list[str]:
    state = get_state(config)
    if not state:
        return []
    out = []
    for u in state.urls:
        low = u.lower()
        if any(h in low for h in CRITICAL_HINTS):
            out.append(u)
    return out[:3]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    endpoints = _critical_endpoints(target, config)
    if not endpoints:
        return findings
    for url in endpoints:
        results: list[int] = []
        success_count = 0
        client = HttpClient(config)

        def hit():
            nonlocal success_count
            r = client.post(url)
            if r is None:
                return
            results.append(r.status_code)
            if r.status_code == 200 and any(s in (r.text or "").lower() for s in SUCCESS):
                success_count += 1

        threads = [threading.Thread(target=hit) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        client.close()
        # Lebih dari 1 sukses dalam burst paralel = mencurigakan
        if success_count >= 2:
            findings.append(Finding(
                module="race_condition",
                title=f"Endpoint `{url}` mungkin rentan race condition",
                severity=Severity.HIGH,
                description=("Mengirim 8 request paralel menghasilkan beberapa respons "
                             "sukses pada endpoint kritis (redeem/claim/withdraw). Ini "
                             "biasanya tanda missing locking — voucher/cashback dapat "
                             "diklaim ganda."),
                target=url,
                evidence=f"success_count={success_count}/8, statuses={results}",
                cwe="CWE-362", confidence="tentative",
                remediation=("Gunakan database transaction + row lock (`SELECT ... FOR UPDATE`), "
                             "atau increment atomic + idempotency key per request."),
            ))
            break
    return findings
