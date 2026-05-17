"""Voucher / coupon flow auditor.

Tujuan: mendeteksi *konfigurasi* voucher/promo yang berisiko, BUKAN
melakukan brute-force kode voucher atau memanipulasi saldo.

Yang dideteksi:
1. Endpoint voucher/coupon/promo terdeteksi (cari URL/form yang URL-nya
   mengandung kata kunci voucher/promo/kupon/diskon).
2. Endpoint apply-voucher tanpa CSRF token.
3. Field discount/percent/amount yang dikirim dari client (potensi
   tampering nilai diskon).
4. Halaman/endpoint admin voucher yang dapat diakses tanpa otentikasi
   (anonim akses ke /admin/coupons, /api/admin/promo, dll.).
5. Daftar voucher yang ter-ekspos di response publik (sample sering muncul
   di JS bundling: `["WELCOME10","NEWUSER50","SUPER100"]`).
6. Daftar test MANUAL yang wajib tester lakukan: brute-force code (limit?),
   stack/replay, expired bypass, negative discount, voucher untuk produk
   lain, dll.

Tool TIDAK menebak kode voucher, TIDAK men-submit voucher, TIDAK menguji
race condition. Itu test manual yang wajib dilakukan tester berpengalaman
di environment sandbox.
"""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# URL hint untuk endpoint voucher/promo
VOUCHER_HINTS = (
    "voucher", "coupon", "promo", "kupon", "diskon", "discount",
    "kode-promo", "kode_promo", "redeem", "claim", "reward",
    "kode-voucher", "promocode", "promo-code",
)

# Field name yang sering jadi vektor tampering nilai
DISCOUNT_FIELD_HINTS = (
    "discount", "diskon", "percent", "persen", "amount",
    "nominal", "value", "potongan", "cashback",
)

# Pattern code voucher di body JS / JSON publik
# Heuristik: kombinasi 4-15 huruf besar/angka, mungkin diapit kutip
VOUCHER_CODE_RE = re.compile(
    r'["\']([A-Z0-9_-]{4,20})["\']\s*[,\]\}]',
)
COMMON_PROMO_WORDS = {
    "WELCOME", "NEWUSER", "DISKON", "PROMO", "SUPER",
    "FLASH", "SALE", "GRAB", "FREE", "FIRST",
    "BIGSALE", "MEGA", "FESTIVE", "RAMADAN",
}


def _is_voucher_url(url: str) -> bool:
    low = url.lower()
    return any(h in low for h in VOUCHER_HINTS)


def _has_csrf(fields: list[str]) -> bool:
    csrf_h = ("csrf", "_token", "authenticity_token", "xsrf",
              "csrfmiddlewaretoken", "__requestverificationtoken")
    return any(any(h in f.lower() for h in csrf_h) for f in fields)


def _has_discount_field(fields: list[str]) -> bool:
    return any(any(h in f.lower() for h in DISCOUNT_FIELD_HINTS) for f in fields)


def _harvest_voucher_codes(text: str) -> list[str]:
    """Cari sample voucher code di body publik."""
    out: set[str] = set()
    for m in VOUCHER_CODE_RE.finditer(text or ""):
        code = m.group(1).upper()
        # filter token random / id / hash (bukan voucher manusiawi)
        if not re.match(r"^[A-Z]+\d*$|^[A-Z]+[-_]\d+$|^[A-Z]+\d+[A-Z]*$", code):
            continue
        # filter common false-positive words
        if code in {"NULL", "TRUE", "FALSE", "TYPE", "NAME", "POST", "GET"}:
            continue
        # voucher biasanya cocok pattern atau memuat keyword promo
        if any(w in code for w in COMMON_PROMO_WORDS) or re.match(r"^[A-Z]{3,}\d{1,4}$", code):
            out.add(code)
        if len(out) >= 30:
            break
    return sorted(out)


def _scan_endpoints(target: Target) -> tuple[list[dict], list[dict]]:
    """Return (voucher_endpoints, voucher_forms) hasil crawler."""
    discovered = getattr(target, "discovered", None)
    if discovered is None:
        return [], []

    eps: list[dict] = []
    forms: list[dict] = []
    for ep in getattr(discovered, "endpoints", []):
        if _is_voucher_url(ep.url):
            eps.append({
                "url": ep.url,
                "method": ep.method,
                "params": list(ep.params or []),
                "source": ep.source,
            })
    for f in getattr(discovered, "forms", []):
        if _is_voucher_url(f.get("url", "")):
            forms.append(f)
    return eps, forms


# Daftar test manual untuk voucher (wajib tester lakukan sendiri)
MANUAL_TESTS = [
    "Brute-force kode voucher: kirim 100 kode random dengan request POST /apply-voucher. "
    "Server harus rate-limit (429) atau lockout setelah N kegagalan.",
    "Voucher stacking: pakai 2 voucher berbeda dalam 1 transaksi yang seharusnya hanya boleh 1.",
    "Voucher replay: pakai voucher yang sudah ter-claim user lain (refresh state, kirim ulang).",
    "Voucher expired bypass: pakai kode yang sudah expired, kirim dengan tanggal client-side dimanipulasi.",
    "Voucher untuk produk salah: voucher 'PROMO_BAJU' diapply ke kategori 'ELEKTRONIK'.",
    "Negative discount: kirim discount=-100 (potongan minus = ditambah saldo) atau percent=110%.",
    "Voucher untuk akun premium dipakai akun gratis: ganti userId di body.",
    "Voucher single-use dipakai 2x oleh user yang sama (race condition: 2 request bersamaan).",
    "Daftar voucher publik: cek /api/promos, /api/active-coupons - apakah ada endpoint yang return list aktif?",
    "Currency abuse: voucher '50% off' diaplikasi ke amount yang dibayar dengan currency lain.",
    "Discount stacking dengan saldo refund: refund partial setelah voucher applied -> apakah voucher dikembalikan?",
    "Min purchase bypass: voucher hanya untuk min Rp 100rb -> coba dengan amount Rp 99rb (boundary).",
    "Voucher untuk akun lain: API /vouchers/{id}/redeem dengan id voucher user lain.",
    "First-time-only voucher dipakai user lama: pakai akun yang sudah pernah belanja, "
    "kirim flag isFirstTime=true di body.",
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        v_eps, v_forms = _scan_endpoints(target)

        # Cek voucher code yang ter-ekspos di halaman publik
        resp = client.get(target.base_url)
        codes_in_main = _harvest_voucher_codes(resp.text if resp else "")
        # juga scan JS file bila ada
        codes_in_js: list[str] = []
        discovered = getattr(target, "discovered", None)
        if discovered is not None:
            for js_url in list(getattr(discovered, "js_urls", []))[:10]:
                jsr = client.get(js_url)
                if jsr is not None and jsr.text:
                    codes_in_js.extend(_harvest_voucher_codes(jsr.text))

        all_codes = sorted(set(codes_in_main + codes_in_js))

        # Bila tidak ada apa-apa, modul ini diam
        if not v_eps and not v_forms and not all_codes:
            return findings

        if v_eps or v_forms:
            findings.append(
                Finding(
                    module="voucher",
                    title=f"Alur voucher/promo terdeteksi ({len(v_eps)} endpoint, {len(v_forms)} form)",
                    severity=Severity.INFO,
                    description=(
                        "Crawler menemukan endpoint/form yang URL-nya mengandung kata "
                        "kunci voucher/promo/kupon/diskon. Modul ini akan mengaudit "
                        "konfigurasi-nya."
                    ),
                    target=target.base_url,
                    evidence="\n".join(
                        [f"  endpoint: [{e['method']}] {e['url']}" for e in v_eps[:10]]
                        + [f"  form: [{f.get('method', 'GET')}] {f.get('url')} fields={f.get('fields')}"
                           for f in v_forms[:10]]
                    ),
                    extra={"endpoints": v_eps, "forms": v_forms},
                )
            )

        # Form tanpa CSRF
        for f in v_forms:
            method = (f.get("method") or "GET").upper()
            if method == "GET":
                continue
            fields = list(f.get("fields") or [])
            if not _has_csrf(fields):
                findings.append(
                    Finding(
                        module="voucher",
                        title=f"Form voucher {method} tanpa anti-CSRF: {f.get('url')}",
                        severity=Severity.HIGH,
                        description=(
                            "Form voucher state-changing tanpa token CSRF. Attacker bisa "
                            "memicu apply/redeem voucher dari sesi korban (mis. claim "
                            "voucher korban via halaman jahat)."
                        ),
                        target=f.get("url", ""),
                        evidence=f"method={method} fields={fields}",
                        cwe="CWE-352",
                        remediation=(
                            "Wajibkan token CSRF + cek SameSite cookie untuk semua "
                            "endpoint voucher."
                        ),
                    )
                )
            if _has_discount_field(fields):
                findings.append(
                    Finding(
                        module="voucher",
                        title=f"Field nilai diskon dikirim dari client: {f.get('url')}",
                        severity=Severity.HIGH,
                        confidence="tentative",
                        description=(
                            "Form voucher memuat field discount/percent/amount yang dikontrol "
                            "client. Bila server mempercayai input ini, attacker bisa kirim "
                            "discount=99 (99%) atau amount=999999 untuk dapat potongan tak wajar."
                        ),
                        target=f.get("url", ""),
                        evidence=f"fields={fields}",
                        cwe="CWE-639",
                        remediation=(
                            "Server WAJIB hitung diskon sendiri berdasarkan voucher code. "
                            "Body request HANYA boleh berisi voucher code & order id; server "
                            "lookup voucher di DB, validasi (active, belum expired, sesuai "
                            "kategori, min purchase OK), dan hitung amount akhir."
                        ),
                        references=[
                            "https://cwe.mitre.org/data/definitions/639.html",
                        ],
                    )
                )

        # Voucher code ter-ekspos
        if all_codes:
            findings.append(
                Finding(
                    module="voucher",
                    title=f"Daftar kode voucher ter-ekspos di response publik ({len(all_codes)} kode)",
                    severity=Severity.MEDIUM,
                    description=(
                        "Pola kode voucher terlihat di body HTML/JS publik. Bila ini adalah "
                        "kode aktif (bukan placeholder), attacker bisa pakai langsung. Bahkan "
                        "kode placeholder pun memberi attacker pola untuk brute-force."
                    ),
                    target=target.base_url,
                    evidence=f"sample: {', '.join(all_codes[:10])}",
                    cwe="CWE-200",
                    remediation=(
                        "Voucher aktif jangan disimpan di JS bundle / HTML render. Kirim hanya "
                        "lewat API setelah otentikasi user. Bila harus tampil (mis. banner "
                        "promo publik), pastikan voucher itu memang ditujukan publik."
                    ),
                )
            )

        # Daftar test manual
        findings.append(
            Finding(
                module="voucher",
                title="Daftar test manual WAJIB untuk alur voucher",
                severity=Severity.INFO,
                description=(
                    "Banyak business-logic flaw voucher (race, replay, stacking, expired bypass) "
                    "tidak bisa dideteksi otomatis. Test berikut harus dilakukan tester di "
                    "sandbox/staging dengan akun test."
                ),
                target=target.base_url,
                evidence="\n".join(f"  - {t}" for t in MANUAL_TESTS),
                remediation=(
                    "Jadwalkan dedicated voucher-flow pentest. Audit log apply-voucher di "
                    "production untuk anomali (1 voucher di-claim 100x, voucher expired diapply, "
                    "discount lebih besar dari max)."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
                ],
            )
        )
    finally:
        client.close()
    return findings
