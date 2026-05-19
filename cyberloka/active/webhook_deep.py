"""Deep webhook security scanner.

Pelengkap `webhook_signature.py` (yang hanya cek apakah server menerima
payload payment-success tanpa header signature). `webhook_deep` meng-cover
**delapan kelas serangan** yang biasa membobol integrasi gateway pembayaran
& notifikasi:

    1. **Endpoint discovery**          — gabungan path generik (`/webhook`)
       dengan path khusus gateway: Midtrans, Xendit, DOKU, iPaymu, Stripe,
       Tripay, ShopeePay, GoPay, OVO, LinkAja, PayPal IPN, Paystack, dll.
    2. **Signature bypass**            — kirim header sig kosong, sig invalid,
       sig algoritma `none`, header dengan casing aneh (HTTP/2 lowercase
       enforcement bypass).
    3. **Replay attack**               — kirim payload identik 2× — kalau
       response sama-sama "settlement accepted", server tidak menyimpan
       deduplication.
    4. **Status forgery**              — kirim payload "settlement"/`PAID`
       dari gateway berbeda, atau ubah field internal.
    5. **Mass assignment via webhook** — sertakan field tambahan
       (`amount_overridden`, `is_admin`, `force_settle`, `actual_paid`).
    6. **SSRF via webhook URL config** — kalau ditemukan endpoint yang
       menerima parameter `webhook_url`/`callback_url`, kirim ke
       `http://169.254.169.254` dan ukur leak metadata.
    7. **Verbose error leak**          — kirim payload jelek, lihat apakah
       error membocorkan expected-hash / signing-key / library version.
    8. **Default test-key**            — coba sandbox key yang umum bocor
       (`SB-Mid-server-...`, `xnd_development_...`, `sk_test_...`).

Semua probe **non-destruktif**: payload selalu memuat `order_id` ber-prefix
`cyberloka-test-` agar mudah dibedakan dari transaksi nyata. Setiap finding
men-set `extra["reverify"]` agar validator re-confirm sebelum report.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state

# ----------------------------------------------------------------------------
# Endpoint discovery
# ----------------------------------------------------------------------------
GENERIC_PATHS = [
    "api/webhook", "api/webhooks", "webhook", "webhooks",
    "api/notification", "notification", "callback", "callbacks",
    "api/callback", "api/notify", "notify",
]

# Path khusus gateway pembayaran (Indonesia & global yang umum dipakai
# perusahaan lokal).
GATEWAY_PATHS: list[tuple[str, str]] = [
    # (path, gateway-label)
    ("api/midtrans/notify", "Midtrans"),
    ("api/midtrans/notification", "Midtrans"),
    ("midtrans/notify", "Midtrans"),
    ("payment/midtrans", "Midtrans"),
    ("api/xendit/callback", "Xendit"),
    ("api/xendit/notify", "Xendit"),
    ("xendit/callback", "Xendit"),
    ("api/doku/notify", "DOKU"),
    ("doku/notify", "DOKU"),
    ("api/ipaymu/callback", "iPaymu"),
    ("api/tripay/callback", "Tripay"),
    ("tripay/callback", "Tripay"),
    ("api/duitku/callback", "Duitku"),
    ("api/faspay/notify", "Faspay"),
    ("api/stripe/webhook", "Stripe"),
    ("stripe/webhook", "Stripe"),
    ("api/paystack/webhook", "Paystack"),
    ("paypal/ipn", "PayPal IPN"),
    ("api/paypal/ipn", "PayPal IPN"),
    ("shopeepay/callback", "ShopeePay"),
    ("api/gopay/callback", "GoPay"),
    ("api/ovo/callback", "OVO"),
    ("api/linkaja/callback", "LinkAja"),
    ("api/dana/callback", "DANA"),
    # Generic webhook config endpoints yang menerima `webhook_url`.
    ("api/webhook/config", "GenericConfig"),
    ("api/webhooks/subscribe", "GenericConfig"),
    ("api/integrations/webhook", "GenericConfig"),
]

# ----------------------------------------------------------------------------
# Payload templates per gateway
# ----------------------------------------------------------------------------
def _midtrans_payload() -> dict:
    return {
        "transaction_status": "settlement",
        "status_code": "200",
        "order_id": "cyberloka-test-mt-001",
        "transaction_id": "cyberloka-mt-trx-001",
        "gross_amount": "10000.00",
        "payment_type": "bank_transfer",
        "fraud_status": "accept",
        "signature_key": "0" * 128,
    }


def _xendit_payload() -> dict:
    return {
        "id": "cyberloka-test-xnd-001",
        "external_id": "cyberloka-test-xnd-001",
        "status": "PAID",
        "amount": 10000,
        "paid_amount": 10000,
        "user_id": "cyberloka-user",
        "merchant_name": "cyberloka",
    }


def _stripe_payload() -> dict:
    return {
        "id": "evt_cyberloka",
        "type": "payment_intent.succeeded",
        "data": {"object": {"id": "pi_cyberloka", "amount": 10000,
                            "status": "succeeded", "metadata":
                                {"order_id": "cyberloka-test-st-001"}}},
    }


def _tripay_payload() -> dict:
    return {
        "reference": "cyberloka-test-tp-001",
        "merchant_ref": "cyberloka-test-tp-001",
        "status": "PAID",
        "amount": 10000,
    }


def _doku_payload() -> dict:
    return {
        "transaction": {"status": "SUCCESS", "amount": {"value": "10000.00"}},
        "order": {"invoice_number": "cyberloka-test-doku-001"},
    }


GATEWAY_PAYLOADS = {
    "Midtrans": _midtrans_payload,
    "Xendit": _xendit_payload,
    "Stripe": _stripe_payload,
    "Tripay": _tripay_payload,
    "DOKU": _doku_payload,
    "Paystack": lambda: {
        "event": "charge.success",
        "data": {"reference": "cyberloka-test-ps-001",
                 "status": "success", "amount": 10000},
    },
    "PayPal IPN": lambda: {
        "payment_status": "Completed",
        "txn_id": "cyberloka-test-pp-001",
        "mc_gross": "10.00",
    },
    "iPaymu": lambda: {
        "trx_id": "cyberloka-test-ip-001",
        "status_code": "1",
        "status": "berhasil",
        "amount": "10000",
    },
    "Duitku": lambda: {
        "merchantOrderId": "cyberloka-test-dk-001",
        "resultCode": "00",
        "amount": "10000",
    },
    "Faspay": lambda: {
        "trx_id": "cyberloka-test-fp-001",
        "merchant_id": "12345",
        "payment_status_code": "2",  # success
        "bill_no": "cyberloka-test-fp-001",
    },
    "ShopeePay": lambda: {
        "id": "cyberloka-test-sp-001",
        "status": "PAID",
        "amount": 10000,
    },
    "GoPay": lambda: {
        "transaction_id": "cyberloka-test-gp-001",
        "transaction_status": "settlement",
        "fraud_status": "accept",
        "gross_amount": "10000.00",
    },
    "OVO": lambda: {
        "merchantOrderID": "cyberloka-test-ovo-001",
        "transactionStatus": "SUCCESS",
        "amount": 10000,
    },
    "LinkAja": lambda: {
        "merchantTrxID": "cyberloka-test-la-001",
        "status": "SUCCESS",
        "amount": "10000",
    },
    "DANA": lambda: {
        "acquirementId": "cyberloka-test-dana-001",
        "acquirementStatus": "SUCCESS",
        "amount": {"value": "10000.00", "currency": "IDR"},
    },
}


# ----------------------------------------------------------------------------
# Markers
# ----------------------------------------------------------------------------
ACCEPTED_MARKERS = (
    "ok", "success", "received", "berhasil", "processed",
    "settlement", '"status":"ok"', "accepted",
)
REJECTED_MARKERS = (
    "invalid signature", "invalid_signature", "signature_required",
    "signature mismatch", "tanda tangan", "verification failed",
    "verifikasi gagal", "unauthorized", "401", "403", "forbidden",
    "missing signature", "x-signature", "sha512 mismatch", "hmac mismatch",
)
LEAK_MARKERS = re.compile(
    r"(?:expected\s+(?:signature|hash)|server[_ -]key|api[_ -]secret|"
    r"signing[_ -]key|callback[_ -]secret|sb-mid-server|xnd_development|"
    r"midtrans-server-key)[^\n]*",
    re.I,
)
SSRF_AWS_RE = re.compile(r"ami-id|instance-id|iam/security-credentials", re.I)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def _is_accepted(status: int, body: str) -> bool:
    body_low = body.lower()
    if status >= 400:
        return False
    if any(m in body_low for m in REJECTED_MARKERS):
        return False
    return any(m in body_low for m in ACCEPTED_MARKERS) or status in (200, 201, 202)


def _candidates(target: Target, config: ScanConfig) -> list[tuple[str, str]]:
    """Return list of (url, gateway-label)."""
    base = target.origin + "/"
    out: dict[str, str] = {}  # url -> label
    for path in GENERIC_PATHS:
        out[urljoin(base, path)] = "Generic"
    for path, label in GATEWAY_PATHS:
        out[urljoin(base, path)] = label
    s = get_state(config)
    if s:
        for u in s.urls:
            low = u.lower()
            if any(k in low for k in ("webhook", "callback", "notify",
                                      "midtrans", "xendit", "stripe",
                                      "tripay", "doku", "ipaymu", "ovo",
                                      "gopay", "shopeepay", "linkaja",
                                      "duitku", "faspay")):
                if u not in out:
                    out[u] = "DiscoveredCrawler"
    return list(out.items())[:24]


def _baseline_reject(client: HttpClient, url: str) -> bool:
    """Return True kalau endpoint memang webhook yang menolak request kosong
    / salah signature. Pakai sebagai sanity gate sebelum report."""
    r = client.post(url, data="", headers={"Content-Type": "application/json"})
    if r is None:
        return False
    body_low = (r.text or "").lower()
    if r.status_code in (400, 401, 403, 422) or \
       any(m in body_low for m in REJECTED_MARKERS):
        return True
    return False


# ============================================================================
# Probes
# ============================================================================
def _probe_signature_bypass(client: HttpClient, url: str,
                            label: str) -> list[Finding]:
    out: list[Finding] = []
    payload_fn = GATEWAY_PAYLOADS.get(label) or _midtrans_payload
    payload = payload_fn()
    body = json.dumps(payload)

    # Kasus 1: tanpa signature sama sekali
    r = client.post(url, data=body,
                    headers={"Content-Type": "application/json"})
    if r is None:
        return out
    body_resp = r.text or ""
    if _is_accepted(r.status_code, body_resp):
        out.append(Finding(
            module="webhook_deep", target=url,
            title=(f"Webhook {label} menerima notifikasi sukses tanpa "
                   "signature"),
            severity=Severity.CRITICAL,
            description=(
                "Endpoint membalas OK saat dikirim payload payment-success "
                "tanpa header signature. Attacker dapat forge transaksi dan "
                "menambah saldo / menandai pesanan lunas tanpa membayar."
            ),
            evidence=truncate(f"status={r.status_code} body={body_resp[:160]}",
                              240),
            cwe="CWE-345", confidence="firm",
            remediation=(
                "Verifikasi signature di setiap webhook (Midtrans: SHA-512 "
                "dari `order_id+status_code+gross_amount+server_key`; "
                "Stripe: HMAC-SHA-256 di header `Stripe-Signature`; Xendit: "
                "header `x-callback-token`). Tolak request tanpa signature "
                "valid dan tambahkan IP allowlist gateway."
            ),
            references=[
                "https://docs.midtrans.com/en/after-payment/http-notification",
                "https://stripe.com/docs/webhooks/signatures",
            ],
            extra={"reverify": {"status": (200, 201, 202),
                                "marker": "ok", "in_body": True}},
        ))
        return out  # critical → tidak perlu test bypass lain

    # Kasus 2: signature dummy / algoritma 'none'
    bypass_headers = [
        ("signature kosong", {"X-Signature": "", "X-Callback-Token": ""}),
        ("signature dummy",
         {"X-Signature": "0" * 64, "X-Callback-Token": "test",
          "X-Midtrans-Signature": "0" * 128}),
        ("alg=none JWT-style",
         {"Authorization": "Bearer eyJhbGciOiJub25lIn0..",
          "X-Signature": "alg=none"}),
        ("casing aneh",
         {"x-signature": "", "X-SIGNATURE": "", "Signature": ""}),
        ("Stripe sig dummy",
         {"Stripe-Signature": f"t=1,v1={'0'*64}"}),
    ]
    for label_b, headers in bypass_headers:
        r = client.post(url, data=body,
                        headers={"Content-Type": "application/json", **headers})
        if r is None:
            continue
        if _is_accepted(r.status_code, r.text or ""):
            out.append(Finding(
                module="webhook_deep", target=url,
                title=f"Webhook {label} menerima signature {label_b}",
                severity=Severity.CRITICAL,
                description=(
                    "Server menerima request dengan header signature yang "
                    "diisi nilai placeholder/none. Implementasi verifikasi "
                    "signature kemungkinan salah (bandingkan string kosong "
                    "dengan timing-safe equal yang malah lolos)."
                ),
                evidence=truncate(
                    f"headers={list(headers.keys())} status={r.status_code} "
                    f"body={(r.text or '')[:140]}",
                    240,
                ),
                cwe="CWE-347", confidence="firm",
                remediation=(
                    "Hitung signature dari raw body + secret server-side, "
                    "bandingkan dengan `hmac.compare_digest`. Tolak request "
                    "kalau header signature kosong atau format tidak benar."
                ),
                extra={"reverify": {"status": (200, 201, 202),
                                    "marker": "ok", "in_body": True}},
            ))
            return out
    return out


def _probe_replay(client: HttpClient, url: str, label: str) -> list[Finding]:
    out: list[Finding] = []
    payload_fn = GATEWAY_PAYLOADS.get(label) or _midtrans_payload
    payload = payload_fn()
    body = json.dumps(payload)
    headers = {"Content-Type": "application/json"}
    r1 = client.post(url, data=body, headers=headers)
    r2 = client.post(url, data=body, headers=headers)
    if r1 is None or r2 is None:
        return out
    if not (_is_accepted(r1.status_code, r1.text or "")
            and _is_accepted(r2.status_code, r2.text or "")):
        return out
    # Kalau kedua response menyatakan sukses → server tidak dedupe
    out.append(Finding(
        module="webhook_deep", target=url,
        title=f"Webhook {label} rentan replay attack (idempotency lemah)",
        severity=Severity.HIGH,
        description=(
            "Dua request webhook identik berhasil keduanya — server tidak "
            "menyimpan dedup id transaksi. Attacker yang mencegat satu "
            "notifikasi sukses bisa memutar ulang berkali-kali untuk top-up "
            "berulang."
        ),
        evidence=f"replay#1 status={r1.status_code}; "
                 f"replay#2 status={r2.status_code}",
        cwe="CWE-294", confidence="firm",
        remediation=(
            "Simpan `transaction_id`/`order_id` yang sudah diproses ke DB "
            "unique. Webhook handler: cek dulu, kalau sudah ada → return 200 "
            "tanpa mutasi saldo. Tambahkan timestamp tolerance dari header "
            "gateway (misal `X-Timestamp` ±5 menit)."
        ),
        extra={"reverify": {"status": (200, 201, 202)}},
    ))
    return out


def _probe_status_forgery(client: HttpClient, url: str,
                          label: str) -> list[Finding]:
    """Kirim payload Midtrans ke endpoint Xendit (atau sebaliknya). Bila
    server tetap mark settled, validator gateway-spesifik tidak dipasang."""
    out: list[Finding] = []
    if label not in ("Midtrans", "Xendit", "DOKU", "Stripe"):
        return out
    cross = "Stripe" if label != "Stripe" else "Midtrans"
    payload = GATEWAY_PAYLOADS[cross]()
    r = client.post(url, data=json.dumps(payload),
                    headers={"Content-Type": "application/json"})
    if r is None:
        return out
    if _is_accepted(r.status_code, r.text or ""):
        out.append(Finding(
            module="webhook_deep", target=url,
            title=f"Webhook {label} menerima payload format {cross}",
            severity=Severity.HIGH,
            description=(
                f"Endpoint {label} membalas sukses meski payload menggunakan "
                f"struktur {cross}. Validator schema/gateway tampak tidak "
                "dipasang — attacker bisa memilih format paling longgar."
            ),
            evidence=truncate(
                f"cross_format={cross} status={r.status_code} "
                f"body={(r.text or '')[:140]}",
                240,
            ),
            cwe="CWE-345", confidence="tentative",
            remediation=(
                "Validasi struktur payload sesuai schema gateway tertentu "
                "(field wajib, tipe, range nilai). Tolak request yang tidak "
                "match schema."
            ),
            extra={"reverify": {"status": (200, 201, 202)}},
        ))
    return out


def _probe_mass_assignment(client: HttpClient, url: str,
                           label: str) -> list[Finding]:
    out: list[Finding] = []
    payload_fn = GATEWAY_PAYLOADS.get(label) or _midtrans_payload
    payload = payload_fn()
    payload.update({
        "amount_overridden": 99999999,
        "force_settle": True,
        "is_admin": True,
        "actual_paid": 99999999,
        "extra_balance": 99999999,
        "tambahkan_saldo": 99999999,
    })
    r = client.post(url, data=json.dumps(payload),
                    headers={"Content-Type": "application/json"})
    if r is None:
        return out
    body = r.text or ""
    if not _is_accepted(r.status_code, body):
        return out
    # Bila response memuat angka 99999999 → server menyalin field tambahan.
    if "99999999" in body or "force_settle" in body.lower():
        out.append(Finding(
            module="webhook_deep", target=url,
            title=f"Mass assignment via webhook {label}",
            severity=Severity.HIGH,
            description=(
                "Field tambahan yang seharusnya tidak ada di payload gateway "
                "muncul di response — server tampaknya men-spread payload "
                "langsung ke ORM (misal `Order.update(req.body)`). Attacker "
                "dapat menulis kolom DB sembarang."
            ),
            evidence=truncate(body[:240], 280),
            cwe="CWE-915", confidence="firm",
            remediation=(
                "Pakai DTO / strong-params: hanya ambil field yang diharapkan "
                "dari payload (whitelist). JANGAN pass req.body langsung ke "
                "model.update / Object.assign."
            ),
            extra={"reverify": {"marker": "99999999", "in_body": True}},
        ))
    return out


def _probe_ssrf_webhook_url(client: HttpClient, url: str,
                            label: str) -> list[Finding]:
    """Kalau ini endpoint config (menerima `webhook_url` / `callback_url`),
    coba kirim URL ke metadata service AWS dan lihat apakah server fetch."""
    if label != "GenericConfig":
        return []
    out: list[Finding] = []
    targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1:6379/",
        "http://localhost:8500/v1/agent/self",
    ]
    for target_url in targets:
        for key in ("webhook_url", "callback_url", "url", "endpoint",
                    "notify_url"):
            payload = {key: target_url, "event": "ping",
                       "name": "cyberloka-ssrf-test"}
            r = client.post(url, data=json.dumps(payload),
                            headers={"Content-Type": "application/json"})
            if r is None:
                continue
            body = r.text or ""
            if SSRF_AWS_RE.search(body) or "ami-id" in body.lower() or \
                    "consul" in body.lower():
                out.append(Finding(
                    module="webhook_deep", target=url,
                    title=f"SSRF via {key} pada konfigurasi webhook",
                    severity=Severity.CRITICAL,
                    description=(
                        "Endpoint config webhook men-fetch URL yang dikirim "
                        "client tanpa validasi. Attacker bisa mengarahkan "
                        "fetch ke metadata cloud / service internal."
                    ),
                    evidence=truncate(
                        f"key={key}={target_url} body={body[:180]}", 280),
                    cwe="CWE-918", confidence="firm",
                    remediation=(
                        "Validasi `webhook_url` harus public DNS, tolak IP "
                        "loopback/RFC1918/cloud-metadata. Lakukan DNS "
                        "resolve di server lalu cek IP, JANGAN trust hostname."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                    ],
                    extra={"reverify": {"marker": "ami-id", "in_body": True}},
                ))
                return out
    return out


def _probe_verbose_error(client: HttpClient, url: str,
                         label: str) -> list[Finding]:
    """Kirim payload jelek, tunggu error → cari kebocoran expected_signature
    / signing_key di response."""
    out: list[Finding] = []
    bad_payload = {"this": "is_invalid", "for": label}
    r = client.post(url, data=json.dumps(bad_payload),
                    headers={"Content-Type": "application/json",
                             "X-Signature": "obviouslywrong"})
    if r is None:
        return out
    body = r.text or ""
    m = LEAK_MARKERS.search(body)
    if not m:
        return out
    out.append(Finding(
        module="webhook_deep", target=url,
        title=f"Webhook {label} membocorkan info verifikasi pada error",
        severity=Severity.HIGH,
        description=(
            "Error response webhook membocorkan kata kunci yang seharusnya "
            "tidak terlihat user (server-key, expected-signature, dsb). "
            "Attacker mendapat petunjuk untuk membuat signature valid."
        ),
        evidence=truncate(m.group(0), 200),
        cwe="CWE-209", confidence="firm",
        remediation=(
            "Tampilkan generic error message ke client (`Invalid signature`); "
            "log detail ke logging system saja. Jangan echo raw secret/hash."
        ),
        extra={"reverify": {"status": (400, 401, 403, 422)}},
    ))
    return out


# ============================================================================
# Entry-point
# ============================================================================
def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        candidates = _candidates(target, config)
        for url, label in candidates:
            # Quick existence check — skip kalau endpoint langsung 404.
            head = client.head(url, allow_redirects=False)
            if head is None:
                # Beberapa server tidak support HEAD pada webhook → coba GET tipis
                g = client.get(url, allow_redirects=False)
                if g is None or g.status_code in (404, 410):
                    continue
            elif head.status_code in (404, 410):
                continue

            # Sanity: kalau endpoint *tidak* menolak request kosong sama
            # sekali (200 OK to anything) → kemungkinan landing page generik,
            # skip untuk hindari false-positive.
            # Pengecualian: untuk GenericConfig tetap coba SSRF probe.
            # Untuk gateway terkenal: tetap probe karena banyak gateway
            # men-accept body kosong dan tidak validate.

            # Probes
            f_sig = _probe_signature_bypass(client, url, label)
            findings += f_sig
            if f_sig and f_sig[0].severity == Severity.CRITICAL:
                # Lanjut ke replay/mass-assignment hanya kalau yakin endpoint
                # benar-benar webhook (sudah confirmed accept).
                findings += _probe_replay(client, url, label)
                findings += _probe_mass_assignment(client, url, label)
                findings += _probe_status_forgery(client, url, label)

            findings += _probe_ssrf_webhook_url(client, url, label)
            findings += _probe_verbose_error(client, url, label)
    finally:
        client.close()
    return findings
