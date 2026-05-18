"""Payment / e-commerce business-logic checks.

Heuristik aman: tidak benar-benar melakukan transaksi. Modul ini mencari
indikasi business-logic flaw umum di endpoint pembayaran/order:

- Parameter harga yang dapat di-tamper di sisi klien (mis. `price`, `amount`).
- Negative-amount atau decimal-overflow (mis. `amount=-100`).
- IDOR pada endpoint order/invoice yang menerima ID numerik.
- Kebocoran kredensial gateway (Midtrans/Stripe/Xendit/Doku) di response/JS.

Modul tidak menyelesaikan transaksi: jika endpoint membutuhkan flow checkout
penuh, hasilnya akan berupa hint/tentative. User wajib re-validasi manual.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state

PRICE_PARAMS = (
    "price", "amount", "total", "harga", "subtotal", "grand_total",
    "biaya", "nominal", "qty", "quantity", "jumlah",
)
ORDER_PATH_HINTS = (
    "order", "invoice", "transaction", "payment", "checkout",
    "pembayaran", "transaksi", "pesanan",
)

# Kebocoran kunci gateway
SECRET_PATTERNS = [
    (re.compile(r"sk_live_[A-Za-z0-9]{20,}"), "Stripe live secret"),
    (re.compile(r"pk_live_[A-Za-z0-9]{20,}"), "Stripe publishable (live)"),
    (re.compile(r"SB-Mid-server-[A-Za-z0-9_-]{10,}"), "Midtrans server key (sandbox)"),
    (re.compile(r"Mid-server-[A-Za-z0-9_-]{10,}"), "Midtrans server key (production)"),
    (re.compile(r"xnd_(?:public|private)_[A-Za-z0-9_-]{20,}"), "Xendit API key"),
    (re.compile(r"BRAINTREE_PRIVATE_KEY|brt_[A-Za-z0-9]{20,}"), "Braintree key"),
    (re.compile(r"DOKU_SECRET|doku_secret_[A-Za-z0-9_-]{10,}"), "Doku secret"),
    (re.compile(r"PAYPAL_CLIENT_SECRET=[A-Za-z0-9_-]{20,}"), "PayPal secret"),
]

ERROR_SIGNS = (
    "amount must be positive",
    "negative amount",
    "invalid amount",
    "amount cannot be negative",
    "harga tidak valid",
)


def _mutate(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    new = []
    replaced = False
    for k, v in params:
        if k.lower() == key.lower():
            new.append((k, value))
            replaced = True
        else:
            new.append((k, v))
    if not replaced:
        new.append((key, value))
    return urlunparse(parsed._replace(query=urlencode(new)))


def _payment_urls(target: Target, config: ScanConfig) -> list[str]:
    state = get_state(config)
    pool = [target.base_url]
    if state:
        pool.extend(state.urls)
        pool.extend(state.param_urls)
    seen: set[str] = set()
    out: list[str] = []
    for u in pool:
        if u in seen:
            continue
        seen.add(u)
        low = u.lower()
        if any(h in low for h in ORDER_PATH_HINTS):
            out.append(u)
            continue
        q = urlparse(u).query
        if any(p in q.lower() for p in PRICE_PARAMS):
            out.append(u)
    return out[:20]


def _payment_forms(config: ScanConfig) -> list[dict]:
    state = get_state(config)
    if not state:
        return []
    out: list[dict] = []
    for form in state.forms:
        names = " ".join(i.get("name", "") for i in form["inputs"]).lower()
        action_low = (form.get("action") or "").lower()
        if any(p in names for p in PRICE_PARAMS) or any(
            h in action_low for h in ORDER_PATH_HINTS
        ):
            out.append(form)
    return out


def _check_secret_leak(client: HttpClient, target: Target) -> list[Finding]:
    findings: list[Finding] = []
    resp = client.get(target.base_url)
    if resp is None:
        return findings
    body = resp.text or ""
    for rgx, label in SECRET_PATTERNS:
        m = rgx.search(body)
        if not m:
            continue
        findings.append(
            Finding(
                module="payment",
                title=f"Potensi kebocoran kredensial gateway: {label}",
                severity=Severity.CRITICAL,
                description=(
                    f"Pola seperti {label} ditemukan pada response/halaman publik. "
                    "Jika benar live secret, attacker bisa membuat transaksi atas nama "
                    "merchant Anda."
                ),
                target=target.base_url,
                evidence=truncate(m.group(0), 80),
                cwe="CWE-200",
                confidence="tentative",
                remediation=(
                    "Pindahkan secret ke server-side env. Rotasi kunci segera. "
                    "Audit bundle JavaScript dan konfigurasi reverse-proxy untuk "
                    "memastikan tidak ada secret yang ter-embed di asset publik."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                ],
            )
        )
    return findings


def _check_negative_amount(client: HttpClient, urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen_urls: set[str] = set()
    for url in urls:
        q = urlparse(url).query
        if not q:
            continue
        for k, _ in parse_qsl(q, keep_blank_values=True):
            if k.lower() not in PRICE_PARAMS or url in seen_urls:
                continue
            for payload in ("-1", "-1000", "0.0001"):
                mutated = _mutate(url, k, payload)
                r = client.get(mutated)
                if r is None:
                    continue
                body = (r.text or "").lower()
                # 200 OK + tidak menampilkan error penolakan = mencurigakan
                if r.status_code == 200 and not any(s in body for s in ERROR_SIGNS):
                    findings.append(
                        Finding(
                            module="payment",
                            title=f"Parameter harga `{k}` menerima nilai abnormal ({payload})",
                            severity=Severity.HIGH,
                            description=(
                                "Endpoint mengembalikan 200 OK saat nilai harga "
                                "diset negatif/sangat kecil. Indikasi validasi sisi "
                                "server lemah; perlu verifikasi manual apakah "
                                "transaksi dapat diselesaikan."
                            ),
                            target=mutated,
                            evidence=f"status={r.status_code}, len={len(r.text or '')}",
                            cwe="CWE-840",
                            confidence="tentative",
                            remediation=(
                                "Validasi nilai harga di server (>=0, batas wajar), "
                                "kalkulasi total dari katalog server-side, jangan "
                                "percayai harga dari klien. Tambahkan integrity check "
                                "(HMAC) pada cart token."
                            ),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation",
                            ],
                        )
                    )
                    seen_urls.add(url)
                    break
            if url in seen_urls:
                break
    return findings


def _check_idor_orders(client: HttpClient, urls: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    candidates: list[tuple[str, str, int]] = []
    for url in urls:
        q = urlparse(url).query
        if not q:
            continue
        for k, v in parse_qsl(q, keep_blank_values=True):
            if v.isdigit() and any(
                h in url.lower() for h in ORDER_PATH_HINTS
            ):
                candidates.append((url, k, int(v)))
                break
    for url, k, n in candidates[:8]:
        for delta in (-1, +1):
            mutated = _mutate(url, k, str(max(1, n + delta)))
            if mutated == url:
                continue
            r = client.get(mutated)
            if r is None or r.status_code != 200:
                continue
            body = (r.text or "")
            # 200 OK pada ID berbeda di endpoint order = sangat mencurigakan
            if any(h in body.lower() for h in ("invoice", "order", "transaksi", "pembayaran")):
                findings.append(
                    Finding(
                        module="payment",
                        title=f"Kemungkinan IDOR pada endpoint order/invoice (`{k}`)",
                        severity=Severity.HIGH,
                        description=(
                            "Mengubah ID numerik di parameter URL endpoint order/invoice "
                            "tetap menghasilkan halaman 200 dengan konten order. Periksa "
                            "apakah otorisasi per-user diterapkan."
                        ),
                        target=mutated,
                        evidence=f"original={n}, probed={n + delta}, status=200",
                        cwe="CWE-639",
                        confidence="tentative",
                        remediation=(
                            "Tambahkan otorisasi per-user pada query database (mis. "
                            "`WHERE id=? AND user_id=?`). Gunakan ID yang tidak dapat "
                            "ditebak (UUID/HMAC) bila perlu."
                        ),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                        ],
                    )
                )
                return findings
    return findings


def _check_form_price_tamper(client: HttpClient, forms: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for form in forms:
        price_inputs = [
            i for i in form["inputs"]
            if i.get("name", "").lower() in PRICE_PARAMS
            and i.get("type") in ("hidden", "text", "number")
        ]
        if price_inputs:
            findings.append(
                Finding(
                    module="payment",
                    title=f"Form pembayaran/checkout mengandung field harga yang dapat di-tamper",
                    severity=Severity.HIGH,
                    description=(
                        "Form mengirim parameter harga/jumlah dari klien (hidden/input). "
                        "Pola ini sering memungkinkan tampering harga di sisi browser."
                    ),
                    target=form.get("action", ""),
                    evidence=", ".join(
                        f"{i.get('name')}={i.get('value') or '?'}" for i in price_inputs
                    ),
                    cwe="CWE-602",
                    confidence="tentative",
                    remediation=(
                        "Hitung total transaksi di server berdasarkan SKU & qty saja. "
                        "Jangan terima `price`/`total` dari klien, atau verifikasi "
                        "nilainya terhadap katalog + tanda tangan server."
                    ),
                )
            )
    return findings


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        findings.extend(_check_secret_leak(client, target))
        urls = _payment_urls(target, config)
        forms = _payment_forms(config)
        findings.extend(_check_form_price_tamper(client, forms))
        if urls:
            findings.extend(_check_negative_amount(client, urls))
            findings.extend(_check_idor_orders(client, urls))
    finally:
        client.close()
    return findings
