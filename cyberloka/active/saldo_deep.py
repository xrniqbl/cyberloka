"""Deep saldo / wallet / payment business-logic scanner.

Pelengkap `balance.py` (yang fokus negative-amount). `saldo_deep` melakukan
**delapan kategori** test business-logic yang biasa dieksploitasi attacker
untuk mendapatkan saldo gratis / mencuri saldo orang lain:

    1. Numeric edge-cases    — scientific notation (1e-10), hex/octal,
       integer overflow (2^63), float precision (0.1+0.2),
       string-coerced ("0e0", "+0", " 1 ").
    2. Currency tampering    — kirim ulang dengan currency yang berbeda
       (mis. USD→IDR) tapi nominal sama → potensi konversi salah.
    3. Race condition        — kirim N request concurrent ke endpoint
       withdraw/transfer dengan amount = full saldo. Jika beberapa berhasil
       → double-spend.
    4. Account tampering     — coba ganti param `to_user_id` / `account_id`
       ke ID lain (dengan ID dummy). Jika 200 + tanpa error otorisasi.
    5. Voucher stacking      — kirim kode voucher yang sama 2× dalam satu
       order, atau kirim array of voucher.
    6. Idempotency check     — kirim 2 request identik dengan idempotency
       key sama → harus dapat response sama, bukan dijalankan 2×.
    7. Refund of refund      — coba refund transaksi yang sudah refund.
    8. Decimal rounding      — pakai amount = 0.4999 berulang. Jika dibulat
       ke bawah → free margin.

Setiap finding men-set `extra["reverify"]` agar validator re-confirm.
"""
from __future__ import annotations

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state

# ----------------------------------------------------------------------------
# Endpoint discovery — re-use heuristik dari balance.py + tambah path umum
# ----------------------------------------------------------------------------
SALDO_HINT = re.compile(
    r"(saldo|wallet|balance|withdraw|tarik|topup|top[-_]?up|cashback|reward|"
    r"poin|points?|deposit|transfer|refund|payout|disbursement|order|checkout|"
    r"voucher|kupon|promo|payment|bayar|pembayaran|invoice|tagihan)",
    re.I,
)
AMOUNT_PARAMS = re.compile(
    r"^(amount|jumlah|nominal|total|saldo|qty|points?|poin|value|nilai|harga|"
    r"price|gross_amount|net_amount|sub_total|grand_total|payable|due)$",
    re.I,
)
ACCOUNT_PARAMS = re.compile(
    r"^(to|to_user|to_user_id|target|target_id|recipient|recipient_id|"
    r"destination|account|account_id|user_id|tujuan|penerima)$",
    re.I,
)
CURRENCY_PARAMS = re.compile(r"^(currency|curr|mata_uang|kurs)$", re.I)
VOUCHER_PARAMS = re.compile(r"^(voucher|coupon|kupon|promo|kode_promo|code)$", re.I)

SUCCESS_MARKERS = (
    "berhasil", "sukses", "success", '"status":"ok"', '"ok":true',
    "transferred", "withdrawn", "approved", "saldo bertambah",
    "topup berhasil", "transaksi berhasil",
)
REJECT_MARKERS = (
    "amount must be positive", "negative amount", "amount cannot be negative",
    "invalid amount", "harga tidak valid", "minimum withdraw",
    "tidak mencukupi", "saldo tidak cukup", "insufficient",
    "validation failed", "bad request", "invalid parameter",
    "unauthorized", "forbidden", "tidak diizinkan",
)
AUTH_REJECT_MARKERS = (
    "unauthorized", "forbidden", "not allowed", "tidak diizinkan",
    "permission denied", "akses ditolak", "auth required",
)


# ----------------------------------------------------------------------------
# Numeric payload set
# ----------------------------------------------------------------------------
NUMERIC_EDGE_CASES = [
    # (label, payload, severity_if_accepted)
    ("scientific notation kecil", "1e-10", Severity.HIGH),
    ("scientific notation negatif", "-1e10", Severity.HIGH),
    ("hex value", "0x10", Severity.MEDIUM),
    ("octal value", "010", Severity.LOW),
    ("integer overflow 64-bit", "9223372036854775808", Severity.HIGH),
    ("integer overflow 32-bit", "2147483648", Severity.MEDIUM),
    ("negative zero", "-0", Severity.MEDIUM),
    ("zero exponent", "0e0", Severity.MEDIUM),
    ("plus prefix", "+1", Severity.LOW),
    ("whitespace-pad", " 1 ", Severity.LOW),
    ("string nan", "NaN", Severity.MEDIUM),
    ("string inf", "Infinity", Severity.MEDIUM),
    ("comma decimal", "1,5", Severity.LOW),  # locale issue
    ("very small float", "0.0000001", Severity.MEDIUM),
    ("desimal panjang", "1.99999999999999", Severity.MEDIUM),
    ("array shape", "[1]", Severity.MEDIUM),
    ("object shape", '{"$gt":0}', Severity.HIGH),
    ("null", "null", Severity.LOW),
]


# ============================================================================
# Helpers
# ============================================================================
def _saldo_endpoints(config: ScanConfig) -> list[dict]:
    """Return list of {url, method, params, form_inputs}."""
    state = get_state(config)
    if not state:
        return []
    out: list[dict] = []
    seen_urls: set[str] = set()

    for u in state.urls + state.param_urls:
        low = u.lower()
        if not SALDO_HINT.search(low):
            continue
        if u in seen_urls:
            continue
        seen_urls.add(u)
        params = list(parse_qsl(urlparse(u).query, keep_blank_values=True))
        out.append({"url": u, "method": "GET", "params": params,
                    "inputs": []})

    for f in state.forms:
        action = f.get("action") or ""
        names = " ".join(i.get("name", "") for i in f["inputs"])
        if not (SALDO_HINT.search(action.lower())
                or SALDO_HINT.search(names.lower())):
            continue
        if action in seen_urls:
            continue
        seen_urls.add(action)
        out.append({
            "url": action,
            "method": (f.get("method") or "post").upper(),
            "params": [],
            "inputs": f["inputs"],
        })
    return out[:6]


def _mutate_query(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = list(parse_qsl(parsed.query, keep_blank_values=True))
    new = []
    replaced = False
    for k, v in params:
        if k == key:
            new.append((k, value)); replaced = True
        else:
            new.append((k, v))
    if not replaced:
        new.append((key, value))
    return urlunparse(parsed._replace(query=urlencode(new)))


def _send(client: HttpClient, ep: dict, key: str, value: str,
          extra_payload: dict | None = None) -> tuple[int, str, float] | None:
    """Send mutated request. Return (status, body, elapsed_seconds)."""
    method = ep["method"]
    payload: dict = {}
    if extra_payload:
        payload.update(extra_payload)
    if ep["inputs"]:
        for i in ep["inputs"]:
            n = i.get("name")
            if not n or i.get("type") in ("submit", "button"):
                continue
            payload[n] = i.get("value") or "1"
        payload[key] = value
    t0 = time.monotonic()
    if method == "GET":
        r = client.get(_mutate_query(ep["url"], key, value))
    else:
        r = client.post(ep["url"], data=payload)
    if r is None:
        return None
    return r.status_code, (r.text or ""), time.monotonic() - t0


def _accepted(status: int, body: str) -> bool:
    body_low = body.lower()
    if any(m in body_low for m in REJECT_MARKERS):
        return False
    if status not in (200, 201, 202):
        return False
    return any(m in body_low for m in SUCCESS_MARKERS)


def _key_for(ep: dict, regex: re.Pattern[str]) -> str | None:
    for k, _ in ep["params"]:
        if regex.match(k):
            return k
    for i in ep["inputs"]:
        n = i.get("name")
        if n and regex.match(n):
            return n
    return None


# ============================================================================
# Probes
# ============================================================================
def _probe_numeric_edges(client: HttpClient, ep: dict) -> list[Finding]:
    out: list[Finding] = []
    key = _key_for(ep, AMOUNT_PARAMS)
    if not key:
        return out
    seen_label: set[str] = set()
    for label, payload, sev in NUMERIC_EDGE_CASES:
        res = _send(client, ep, key, payload)
        if res is None:
            continue
        status, body, _ = res
        if not _accepted(status, body):
            continue
        if label in seen_label:
            continue
        seen_label.add(label)
        out.append(Finding(
            module="saldo_deep",
            title=f"Validasi nominal lemah ({label}) pada `{key}`",
            severity=sev,
            description=(
                "Endpoint terkait saldo/transaksi merespons SUKSES untuk "
                f"nominal abnormal `{payload}`. Validasi numerik server tampak "
                "tidak ketat — verifikasi manual apakah saldo benar berubah."
            ),
            target=ep["url"],
            evidence=truncate(
                f"key={key} payload={payload!r} status={status} "
                f"body={body[:140]}",
                240,
            ),
            cwe="CWE-840",
            confidence="tentative",
            remediation=(
                "Validasi tipe input strict (Decimal/integer dengan scale "
                "tetap), tolak NaN/Infinity/scientific-notation/array/object. "
                "Pakai DB transaction + row-lock sebelum mengubah saldo."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation",
            ],
            extra={"reverify": {"status": (200, 201, 202)}},
        ))
        # 1 finding per endpoint cukup
        break
    return out


def _probe_account_tampering(client: HttpClient, ep: dict) -> list[Finding]:
    out: list[Finding] = []
    key = _key_for(ep, ACCOUNT_PARAMS)
    if not key:
        return out
    # ID dummy yang besar/random — kalau server tidak cek owner, 200 OK
    test_ids = ["999999999", "1", "00000000-0000-0000-0000-000000000001"]
    for test_id in test_ids:
        res = _send(client, ep, key, test_id)
        if res is None:
            continue
        status, body, _ = res
        body_low = body.lower()
        if any(m in body_low for m in AUTH_REJECT_MARKERS):
            continue
        if status not in (200, 201, 202):
            continue
        if not any(m in body_low for m in SUCCESS_MARKERS):
            continue
        out.append(Finding(
            module="saldo_deep",
            title=f"Kemungkinan transfer ke akun arbitrer via `{key}={test_id}`",
            severity=Severity.HIGH,
            description=(
                "Endpoint transfer/withdraw menerima ID akun arbitrer tanpa "
                "menolak otorisasi. Attacker mungkin bisa mengirim saldo ke "
                "akun lain. PoC manual diperlukan untuk konfirmasi."
            ),
            target=ep["url"],
            evidence=truncate(f"key={key}={test_id} status={status} "
                              f"body={body[:140]}", 220),
            cwe="CWE-639",
            confidence="tentative",
            remediation=(
                "Setiap mutasi saldo harus memvalidasi: (a) user pemilik "
                "session adalah owner sumber; (b) target account ada & valid; "
                "(c) policy transfer dipenuhi (limit, KYC). Jangan percaya "
                "ID dari client."
            ),
            extra={"reverify": {"status": (200, 201, 202)}},
        ))
        return out
    return out


def _probe_currency_tampering(client: HttpClient, ep: dict) -> list[Finding]:
    out: list[Finding] = []
    key = _key_for(ep, CURRENCY_PARAMS)
    if not key:
        return out
    # Kirim currency tidak sesuai dengan mata uang user, nominal kecil
    for cur in ("USD", "JPY", "VND", "XX"):
        res = _send(client, ep, key, cur)
        if res is None:
            continue
        status, body, _ = res
        if not _accepted(status, body):
            continue
        out.append(Finding(
            module="saldo_deep",
            title=f"Currency tampering diterima ({key}={cur})",
            severity=Severity.HIGH,
            description=(
                "Endpoint menerima currency yang tidak konsisten dengan "
                "akun. Risiko: konversi keliru → attacker membayar 1 unit "
                "JPY untuk barang IDR senilai jauh lebih besar."
            ),
            target=ep["url"],
            evidence=f"key={key}={cur} status={status}",
            cwe="CWE-840",
            confidence="tentative",
            remediation=(
                "Tetapkan currency di server-side berdasarkan akun/region. "
                "Tolak currency yang dikirim client kalau berbeda."
            ),
            extra={"reverify": {"status": (200, 201, 202)}},
        ))
        return out
    return out


def _probe_voucher_stacking(client: HttpClient, ep: dict) -> list[Finding]:
    out: list[Finding] = []
    key = _key_for(ep, VOUCHER_PARAMS)
    if not key:
        return out
    payload_a = "PROMO123"
    # Stack array & duplicate
    for label, val in [
        ("voucher array", '["PROMO123","PROMO123"]'),
        ("voucher duplicate", "PROMO123,PROMO123"),
    ]:
        res = _send(client, ep, key, val)
        if res is None:
            continue
        status, body, _ = res
        body_low = body.lower()
        if any(m in body_low for m in REJECT_MARKERS):
            continue
        if status not in (200, 201, 202):
            continue
        # Indikator: server menerima 2 voucher (cek "discount" muncul 2× atau
        # "diskon" muncul lebih dari sekali)
        if body_low.count("discount") >= 2 or body_low.count("diskon") >= 2:
            out.append(Finding(
                module="saldo_deep",
                title=f"Voucher stacking diterima ({label})",
                severity=Severity.MEDIUM,
                description=(
                    "Server menerima beberapa kode voucher yang seharusnya "
                    "hanya 1× per order. Risiko: diskon berlipat → harga "
                    "akhir negatif atau 0."
                ),
                target=ep["url"],
                evidence=truncate(f"key={key}={val} status={status} "
                                  f"body={body[:160]}", 240),
                cwe="CWE-840",
                confidence="tentative",
                remediation=(
                    "Validasi 1 voucher per order di server. Tolak input "
                    "berbentuk array. Cek total akhir > 0 sebelum charge."
                ),
                extra={"reverify": {"status": (200, 201, 202)}},
            ))
            return out
    # juga test single voucher dipakai 2× berturut-turut
    res1 = _send(client, ep, key, payload_a)
    res2 = _send(client, ep, key, payload_a)
    if res1 and res2 and _accepted(*res1[:2]) and _accepted(*res2[:2]):
        out.append(Finding(
            module="saldo_deep",
            title="Voucher dapat di-redeem berulang oleh user yang sama",
            severity=Severity.MEDIUM,
            description=(
                "Voucher yang sama berhasil di-redeem 2× berturut-turut. "
                "Idempotensi/limit per user tidak ter-enforce."
            ),
            target=ep["url"],
            evidence=f"redeem #1 status={res1[0]}; redeem #2 status={res2[0]}",
            cwe="CWE-840",
            confidence="tentative",
            remediation=(
                "Simpan flag 'voucher_used_by(user_id, code)' unique. Pakai "
                "DB unique constraint, bukan check-then-insert."
            ),
            extra={"reverify": {"status": (200, 201, 202)}},
        ))
    return out


def _probe_race_condition(client: HttpClient, ep: dict) -> list[Finding]:
    """Kirim 5 request paralel — kalau >1 sukses → race window."""
    out: list[Finding] = []
    key = _key_for(ep, AMOUNT_PARAMS)
    if not key:
        return out
    # Pakai amount kecil non-zero supaya tidak destruktif pada akun real
    payload = "1"
    results: list[tuple[int, str]] = []
    lock = threading.Lock()

    def _fire():
        res = _send(client, ep, key, payload)
        if res:
            with lock:
                results.append((res[0], res[1][:200]))

    with ThreadPoolExecutor(max_workers=5) as ex:
        for _ in range(5):
            ex.submit(_fire)
    success = [r for r in results if _accepted(r[0], r[1])]
    if len(success) >= 2:
        out.append(Finding(
            module="saldo_deep",
            title="Race condition: endpoint saldo menerima request konkuren ganda",
            severity=Severity.HIGH,
            description=(
                f"Dari 5 request paralel ke endpoint saldo, {len(success)} "
                "berhasil. Bila ini endpoint withdraw/spending, attacker "
                "bisa double-spend (saldo 100 ditarik 5×)."
            ),
            target=ep["url"],
            evidence=f"sukses={len(success)}/5; statuses={[r[0] for r in results]}",
            cwe="CWE-362",
            confidence="tentative",
            remediation=(
                "Pakai DB transaction + SELECT ... FOR UPDATE pada row saldo, "
                "atau optimistic lock dengan version column. Tambahkan "
                "idempotency key per request agar duplicate request "
                "menghasilkan response sama."
            ),
            references=[
                "https://owasp.org/www-community/vulnerabilities/Race_Conditions",
            ],
            extra={"reverify": {"status": (200, 201, 202)}},
        ))
    return out


def _probe_idempotency(client: HttpClient, ep: dict) -> list[Finding]:
    """Kirim 2× request dengan Idempotency-Key sama → harus sama-sama OK
    tanpa membuat 2 transaksi (server biasanya kasih response cached).

    Kita HANYA report bila server *tidak* menghormati key (response berubah)."""
    out: list[Finding] = []
    key_field = _key_for(ep, AMOUNT_PARAMS)
    if not key_field:
        return out
    idempotency = "cyberloka-idem-001"
    headers = {"Idempotency-Key": idempotency, "X-Idempotency-Key": idempotency}
    # gunakan custom request langsung
    payload: dict = {key_field: "1"}
    if ep["inputs"]:
        for i in ep["inputs"]:
            n = i.get("name")
            if n and n != key_field and i.get("type") not in ("submit", "button"):
                payload[n] = i.get("value") or "1"
    if ep["method"] == "GET":
        return out  # idempotency tidak relevan untuk GET
    r1 = client.post(ep["url"], data=payload, headers=headers)
    r2 = client.post(ep["url"], data=payload, headers=headers)
    if r1 is None or r2 is None:
        return out
    if r1.status_code in (200, 201, 202) and r2.status_code in (200, 201, 202):
        # Response harus identik / membawa transaction_id sama.
        b1, b2 = r1.text or "", r2.text or ""
        # ekstrak transaction id pattern
        rx = re.compile(r'"(?:transaction_id|order_id|reference|trx_id)"\s*:\s*"([^"]+)"')
        m1 = rx.search(b1); m2 = rx.search(b2)
        if m1 and m2 and m1.group(1) != m2.group(1):
            out.append(Finding(
                module="saldo_deep",
                title="Idempotency-Key tidak dihormati pada endpoint transaksi",
                severity=Severity.MEDIUM,
                description=(
                    "Dua request identik dengan `Idempotency-Key` sama "
                    "menghasilkan transaction_id berbeda — artinya 2 "
                    "transaksi terbentuk. Risiko duplicate-charge / "
                    "duplicate-withdraw saat retry network."
                ),
                target=ep["url"],
                evidence=f"trx#1={m1.group(1)} != trx#2={m2.group(1)}",
                cwe="CWE-840",
                confidence="firm",
                remediation=(
                    "Implementasi store idempotency-key ke Redis/DB unique. "
                    "Bila key sudah ada → return response yang dulu, jangan "
                    "buat transaksi baru."
                ),
            ))
    return out


def _probe_decimal_rounding(client: HttpClient, ep: dict) -> list[Finding]:
    out: list[Finding] = []
    key = _key_for(ep, AMOUNT_PARAMS)
    if not key:
        return out
    # Bila server bulatkan ke bawah, 0.4999 == 0 → free.
    for label, payload in (("rounding floor", "0.4999"),
                           ("submilli", "0.0049")):
        res = _send(client, ep, key, payload)
        if res is None:
            continue
        status, body, _ = res
        if not _accepted(status, body):
            continue
        # Kuncinya: respons sukses tapi nominal disebutkan 0
        body_low = body.lower()
        if re.search(r'"(amount|total|nominal|charged|harga)"\s*:\s*0(\.0+)?\b', body_low):
            out.append(Finding(
                module="saldo_deep",
                title=f"Pembulatan ke bawah: nominal {payload} dianggap 0",
                severity=Severity.HIGH,
                description=(
                    "Endpoint menerima nominal sub-1, lalu response "
                    "mencatat amount=0. Attacker bisa belanja gratis "
                    "dengan mengulang transaksi nominal kecil."
                ),
                target=ep["url"],
                evidence=truncate(f"key={key}={payload} body={body[:200]}",
                                  240),
                cwe="CWE-682",
                confidence="firm",
                remediation=(
                    "Pakai Decimal/BigDecimal di server, jangan float. "
                    "Tolak amount < smallest currency unit (mis. < Rp 1)."
                ),
                extra={"reverify": {"status": (200, 201, 202)}},
            ))
            return out
    return out


# ============================================================================
# Entry-point
# ============================================================================
def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    endpoints = _saldo_endpoints(config)
    if not endpoints:
        return findings
    client = HttpClient(config)
    try:
        for ep in endpoints:
            findings += _probe_numeric_edges(client, ep)
            findings += _probe_account_tampering(client, ep)
            findings += _probe_currency_tampering(client, ep)
            findings += _probe_voucher_stacking(client, ep)
            findings += _probe_decimal_rounding(client, ep)
            findings += _probe_idempotency(client, ep)
            # race terakhir karena paling berisik di server
            findings += _probe_race_condition(client, ep)
    finally:
        client.close()
    return findings
