"""Webhook signature validation probe.

If endpoint accepts payment-callback POST without verifying signature,
attacker can forge "transaction success" notifications.
"""
from __future__ import annotations

import json
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

# Common webhook paths
WEBHOOK_PATHS = [
    "/api/webhook", "/api/webhooks", "/webhook", "/webhooks",
    "/api/payment/notify", "/api/payment/callback", "/payment/notify",
    "/payment/callback", "/midtrans/notify", "/xendit/callback",
    "/api/midtrans", "/api/xendit", "/api/doku/notify",
    "/api/notification", "/notification/payment", "/api/transaction/notify",
]

# Payload yang dipakai untuk forge "transaksi sukses" (Midtrans-style)
FORGE_PAYLOAD = {
    "transaction_status": "settlement",
    "status_code": "200",
    "order_id": "cyberloka-test-order-1",
    "transaction_id": "cyberloka-test-txn-1",
    "gross_amount": "10000.00",
    "payment_type": "bank_transfer",
    "fraud_status": "accept",
}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    base = target.origin + "/"
    try:
        candidates = set()
        for p in WEBHOOK_PATHS:
            candidates.add(urljoin(base, p.lstrip("/")))

        s = get_state(config)
        if s:
            for u in s.urls:
                low = u.lower()
                if any(h in low for h in ("webhook", "callback", "notify", "midtrans", "xendit", "doku")):
                    candidates.add(u)

        for url in list(candidates)[:10]:
            r = client.post(url, json=FORGE_PAYLOAD,
                            headers={"Content-Type": "application/json"})
            if r is None or r.status_code >= 500:
                continue
            body = (r.text or "").lower()
            # 200 OK + body indicating accepted = likely vulnerable
            accepted_markers = ("ok", "success", "received", "berhasil",
                                "processed", "settlement")
            rejected_markers = ("invalid signature", "signature", "unauthorized",
                                "401", "403", "tanda tangan", "verification failed")
            if r.status_code in (200, 201, 202) and \
               any(m in body for m in accepted_markers) and \
               not any(m in body for m in rejected_markers):
                findings.append(Finding(
                    module="webhook_signature", target=url,
                    title=f"Webhook menerima payload tanpa verifikasi signature: {url}",
                    severity=Severity.CRITICAL,
                    confidence="tentative",
                    description=("Endpoint webhook menerima payload payment-success tanpa "
                                 "header signature. Attacker dapat forge notifikasi 'transaksi "
                                 "sukses' palsu — saldo masuk tanpa pembayaran asli."),
                    evidence=f"POST status={r.status_code}, no signature rejection",
                    cwe="CWE-345",
                    remediation=("Verifikasi signature di setiap webhook (Midtrans: SHA512 hash; "
                                 "Stripe: HMAC-SHA256 di header `Stripe-Signature`; "
                                 "Xendit: header `x-callback-token`). Tolak request tanpa "
                                 "signature valid + IP allowlist gateway."),
                    references=[
                        "https://midtrans.com/id/blog/cara-verifikasi-status-transaksi-secara-aman",
                        "https://stripe.com/docs/webhooks/signatures",
                    ],
                ))
                return findings
    finally:
        client.close()
    return findings
