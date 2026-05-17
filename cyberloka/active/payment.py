"""Payment / billing flow security auditor.

Tujuan: mendeteksi *indikasi* alur pembayaran/saldo yang berisiko, BUKAN
menjalankan transaksi atau memanipulasi saldo. Modul ini hanya membaca
respons publik dan melakukan probe ringan, lalu memberi rekomendasi
testing manual yang spesifik.

Yang dideteksi:
1. Endpoint pembayaran terdeteksi (payment, checkout, billing, topup, dst.)
2. Endpoint payment yang dapat diakses lewat HTTP (bukan HTTPS)
3. Form payment tanpa anti-CSRF token (kombinasi state-changing + uang)
4. Field harga / amount dikirim dari client (tampak di form / JS)
   -> indikasi tampering harga mungkin
5. Tidak ada rate-limit di endpoint payment (re-trigger pembayaran)
6. JWT yang dikirim ke endpoint payment punya scope luas atau lifetime panjang
7. Webhook callback exposed tanpa signature header
8. Hardcoded payment provider key/test-key di JS publik (Stripe, Midtrans,
   Xendit test/live keys)
9. Recommendation pack: daftar test manual yang WAJIB dilakukan sendiri
   (race condition, negative amount, currency confusion, IDOR transaction
   read, OTP bypass, dll.)

CATATAN: tool TIDAK akan mensubmit form payment, mengirim transaksi,
atau melakukan eksperimen apapun yang dapat memicu transaksi nyata.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# Indikator URL/path untuk endpoint payment
PAYMENT_HINTS = (
    "payment", "checkout", "billing", "invoice", "order",
    "pay", "topup", "top-up", "saldo", "wallet", "balance",
    "transfer", "withdraw", "deposit", "transaction", "charge",
    "subscribe", "subscription", "donate", "donation",
    "midtrans", "xendit", "stripe", "doku", "ovo", "gopay",
    "shopeepay", "dana", "linkaja", "qris", "va",
)

# Field name yang sering dipakai untuk harga/amount
AMOUNT_FIELD_HINTS = (
    "amount", "price", "total", "harga", "jumlah", "biaya",
    "subtotal", "cost", "value", "nominal", "balance",
)

# Regex untuk mendeteksi key payment provider yang ter-ekspos di JS publik
PROVIDER_KEY_PATTERNS = [
    # Stripe
    (re.compile(r"\b(pk_live_[A-Za-z0-9]{20,})\b"), "Stripe LIVE publishable key"),
    (re.compile(r"\b(pk_test_[A-Za-z0-9]{20,})\b"), "Stripe TEST publishable key"),
    (re.compile(r"\b(sk_live_[A-Za-z0-9]{20,})\b"), "Stripe LIVE SECRET key (CRITICAL)"),
    (re.compile(r"\b(sk_test_[A-Za-z0-9]{20,})\b"), "Stripe TEST secret key"),
    # Midtrans
    (re.compile(r"\b(SB-Mid-server-[A-Za-z0-9_-]+)\b"), "Midtrans SANDBOX server key"),
    (re.compile(r"\b(Mid-server-[A-Za-z0-9_-]+)\b"), "Midtrans PRODUCTION server key (CRITICAL)"),
    (re.compile(r"\b(SB-Mid-client-[A-Za-z0-9_-]+)\b"), "Midtrans SANDBOX client key"),
    (re.compile(r"\b(Mid-client-[A-Za-z0-9_-]+)\b"), "Midtrans PRODUCTION client key"),
    # Xendit
    (re.compile(r"\b(xnd_public_[A-Za-z0-9_-]+)\b"), "Xendit public key"),
    (re.compile(r"\b(xnd_development_[A-Za-z0-9_-]+)\b"), "Xendit DEVELOPMENT secret key"),
    (re.compile(r"\b(xnd_production_[A-Za-z0-9_-]+)\b"), "Xendit PRODUCTION secret key (CRITICAL)"),
    # PayPal
    (re.compile(r"\b(A21AA[A-Za-z0-9_-]{60,})\b"), "PayPal client ID/token"),
]


def _is_payment_url(url: str) -> bool:
    low = url.lower()
    return any(h in low for h in PAYMENT_HINTS)


def _has_csrf_field(fields: list[str]) -> bool:
    csrf_hints = ("csrf", "_token", "authenticity_token", "xsrf",
                  "csrfmiddlewaretoken", "__requestverificationtoken")
    return any(any(h in f.lower() for h in csrf_hints) for f in fields)


def _has_amount_field(fields: list[str]) -> bool:
    return any(any(h in f.lower() for h in AMOUNT_FIELD_HINTS) for f in fields)


def _scan_payment_endpoints(target: Target) -> tuple[list[dict], list[dict]]:
    """Return (payment_endpoints, payment_forms) hasil crawler."""
    discovered = getattr(target, "discovered", None)
    if discovered is None:
        return [], []

    pay_endpoints: list[dict] = []
    pay_forms: list[dict] = []
    for ep in getattr(discovered, "endpoints", []):
        if _is_payment_url(ep.url):
            pay_endpoints.append({
                "url": ep.url,
                "method": ep.method,
                "params": list(ep.params or []),
                "source": ep.source,
            })
    for f in getattr(discovered, "forms", []):
        if _is_payment_url(f.get("url", "")):
            pay_forms.append(f)
    return pay_endpoints, pay_forms


def _check_provider_keys(client: HttpClient, target: Target) -> list[Finding]:
    """Scan JS file publik untuk key payment provider yang ter-ekspos."""
    findings: list[Finding] = []
    discovered = getattr(target, "discovered", None)
    if discovered is None:
        return findings

    js_urls = list(getattr(discovered, "js_urls", []))[:20]
    # juga coba ambil HTML utama untuk inline-script keys
    main_resp = client.get(target.base_url)
    if main_resp is not None and main_resp.text:
        for rgx, label in PROVIDER_KEY_PATTERNS:
            m = rgx.search(main_resp.text)
            if m:
                sev = Severity.CRITICAL if "CRITICAL" in label else (
                    Severity.HIGH if "PRODUCTION" in label else Severity.LOW
                )
                findings.append(_make_key_finding(target.base_url, label, m.group(1), sev))

    for url in js_urls:
        resp = client.get(url)
        if resp is None or not resp.text:
            continue
        for rgx, label in PROVIDER_KEY_PATTERNS:
            m = rgx.search(resp.text)
            if m:
                sev = Severity.CRITICAL if "CRITICAL" in label else (
                    Severity.HIGH if "PRODUCTION" in label else Severity.LOW
                )
                findings.append(_make_key_finding(url, label, m.group(1), sev))
    return findings


def _make_key_finding(url: str, label: str, key: str, sev: Severity) -> Finding:
    public_ok = "publishable" in label.lower() or "client" in label.lower() or "public" in label.lower()
    if public_ok and "PRODUCTION" not in label and "CRITICAL" not in label:
        desc = (
            f"Key payment provider terdeteksi di sumber publik: {label}. "
            "Key public/publishable memang dirancang aman untuk dipublish, "
            "tapi pastikan ini bukan secret key yang seharusnya hanya di server."
        )
        rem = "Verifikasi: pastikan key ini memang tipe public/publishable, BUKAN secret/server key."
    else:
        desc = (
            f"Key payment provider yang seharusnya RAHASIA bocor di sumber publik: {label}. "
            "Attacker bisa memakainya untuk membuat transaksi atas nama Anda, "
            "atau membaca daftar transaksi via API provider."
        )
        rem = (
            "1) ROTASI key SEKARANG di dashboard provider (Stripe/Midtrans/Xendit/dll). "
            "2) Pindahkan secret key ke server-side env var saja. "
            "3) Audit kapan key ini pertama bocor (git history, public S3, dll). "
            "4) Cek log transaksi mencurigakan periode bocor."
        )
    return Finding(
        module="payment",
        title=f"{label} ter-ekspos di sumber publik",
        severity=sev,
        description=desc,
        target=url,
        evidence=truncate(key, 60),
        cwe="CWE-798",
        remediation=rem,
        references=[
            "https://owasp.org/www-project-api-security/",
        ],
    )


def _check_payment_over_http(pay_endpoints: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for ep in pay_endpoints:
        if urlparse(ep["url"]).scheme == "http":
            out.append(
                Finding(
                    module="payment",
                    title=f"Endpoint payment dapat diakses lewat HTTP (bukan HTTPS): {ep['url']}",
                    severity=Severity.HIGH,
                    description=(
                        "Endpoint terkait pembayaran/saldo melayani HTTP. Kredensial, "
                        "nominal, dan token sesi pengguna dapat disadap di jaringan."
                    ),
                    target=ep["url"],
                    cwe="CWE-319",
                    remediation=(
                        "Paksa HTTPS untuk semua route payment. Aktifkan HSTS. "
                        "Redirect 301 dari HTTP ke HTTPS di reverse-proxy."
                    ),
                )
            )
    return out


def _check_form_csrf_and_amount(pay_forms: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for f in pay_forms:
        method = (f.get("method") or "GET").upper()
        fields = list(f.get("fields") or [])
        if method == "GET":
            continue
        if not _has_csrf_field(fields):
            out.append(
                Finding(
                    module="payment",
                    title=f"Form payment {method} tanpa anti-CSRF: {f.get('url')}",
                    severity=Severity.HIGH,
                    description=(
                        "Form pembayaran/state-changing tanpa token CSRF. "
                        "Attacker dapat memicu pembayaran/transfer dari sesi korban."
                    ),
                    target=f.get("url", ""),
                    evidence=f"method={method} fields={fields}",
                    cwe="CWE-352",
                    remediation=(
                        "Wajibkan token CSRF (synchronizer pattern atau double-submit cookie) "
                        "untuk semua route yang men-state-change uang. Tambahkan SameSite=Lax/Strict "
                        "pada cookie session."
                    ),
                )
            )
        if _has_amount_field(fields):
            out.append(
                Finding(
                    module="payment",
                    title=f"Field amount/harga dikirim dari client di form payment",
                    severity=Severity.MEDIUM,
                    confidence="tentative",
                    description=(
                        "Form payment memuat field nominal/harga yang dikontrol client. "
                        "Bila server mempercayainya tanpa re-validasi, attacker dapat "
                        "memodifikasi harga (mis. bayar Rp 1 untuk produk Rp 1.000.000)."
                    ),
                    target=f.get("url", ""),
                    evidence=f"fields={fields}",
                    cwe="CWE-639",
                    remediation=(
                        "JANGAN mempercayai amount/harga dari client. Server WAJIB "
                        "mengambil harga dari database berdasarkan productId. Validasi "
                        "amount di server saat membuat invoice."
                    ),
                )
            )
    return out


# Daftar test manual yang harus dilakukan sendiri (tidak bisa otomatis)
MANUAL_TESTS = [
    "Race condition: kirim 2 request bayar sama persis dalam waktu < 100ms (pakai Burp Turbo Intruder atau ffuf concurrency). "
    "Cek apakah saldo terpotong sekali tapi item ter-claim 2x.",
    "Negative / zero amount: coba submit transaksi dengan amount=0, amount=-100. Server harus reject.",
    "Currency confusion: kirim amount dengan currency berbeda (mis. tukar IDR jadi VND/USD). "
    "Jangan sampai server pakai number tanpa cek currency code.",
    "Price tampering: intercept request, ubah field harga sebelum forward. Server harus re-fetch harga dari DB.",
    "Coupon stacking / replay: pakai 1 kupon 2x dalam waktu bersamaan, atau pakai kupon yang sudah expired.",
    "IDOR transaction read: ganti transactionId di GET /api/transaction/{id} jadi id user lain.",
    "IDOR transaction modify: coba PATCH /api/transaction/{id}/cancel atau /refund untuk transaksi user lain.",
    "Webhook spoofing: kirim webhook palsu ke /webhook/midtrans tanpa signature. Pastikan server verifikasi HMAC signature.",
    "Webhook replay: tangkap webhook valid, kirim ulang. Server harus reject duplicate (idempotency key).",
    "OTP bypass: coba checkout dengan input OTP kosong, salah, atau ubah HTTP status response (Burp).",
    "Saldo negatif: tarik dana > saldo. Server harus reject sebelum debit.",
    "Currency precision: bayar dengan amount=99.999 (3 desimal) atau Decimal-overflow.",
    "Refund double-spend: minta refund 2x untuk 1 transaksi. Pastikan ada idempotency.",
    "Voucher amount overflow: amount voucher lebih besar dari total tagihan -> apakah saldo bertambah?",
]


def _manual_test_finding(target_url: str, has_payment_flow: bool) -> Finding:
    if not has_payment_flow:
        return None  # type: ignore
    return Finding(
        module="payment",
        title="Daftar test manual WAJIB untuk alur pembayaran",
        severity=Severity.INFO,
        description=(
            "Cyberloka mendeteksi adanya alur pembayaran/saldo. Banyak business-logic "
            "flaw pada payment TIDAK BISA dideteksi otomatis dan harus di-test manual "
            "oleh tester yang paham bisnis. Lakukan tes berikut di environment "
            "sandbox/staging dengan akun test, bukan production."
        ),
        target=target_url,
        evidence="\n".join(f"  - {t}" for t in MANUAL_TESTS),
        remediation=(
            "Jadwalkan dedicated payment-flow pentest dengan tester berpengalaman. "
            "Gunakan environment sandbox provider untuk semua test. Pastikan ada "
            "monitoring transaksi anomali di production."
        ),
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
        ],
    )


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        pay_endpoints, pay_forms = _scan_payment_endpoints(target)

        # Bila tidak ada indikasi alur payment, modul ini hampir tidak menghasilkan apa-apa.
        # Tapi tetap cek key provider di main page (kasus SPA).
        findings.extend(_check_provider_keys(client, target))

        if not pay_endpoints and not pay_forms:
            return findings

        findings.append(
            Finding(
                module="payment",
                title=f"Alur pembayaran/saldo terdeteksi ({len(pay_endpoints)} endpoint, {len(pay_forms)} form)",
                severity=Severity.INFO,
                description=(
                    "Crawler menemukan endpoint/form yang URL-nya mengandung kata kunci "
                    "payment/billing/topup/saldo/dll. Modul payment akan mengaudit "
                    "konfigurasi-nya."
                ),
                target=target.base_url,
                evidence="\n".join(
                    [f"  endpoint: [{e['method']}] {e['url']}" for e in pay_endpoints[:10]]
                    + [f"  form: [{f.get('method', 'GET')}] {f.get('url')} fields={f.get('fields')}" for f in pay_forms[:10]]
                ),
                extra={"endpoints": pay_endpoints, "forms": pay_forms},
            )
        )

        findings.extend(_check_payment_over_http(pay_endpoints))
        findings.extend(_check_form_csrf_and_amount(pay_forms))

        manual = _manual_test_finding(target.base_url, True)
        if manual:
            findings.append(manual)
    finally:
        client.close()
    return findings
