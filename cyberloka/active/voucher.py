"""Voucher / kupon abuse checks (heuristic, safe)."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

VOUCHER_PARAMS = (
    "voucher", "coupon", "code", "promo", "promocode", "discount",
    "kupon", "kode_promo", "redeem",
)
VOUCHER_FIELDS = re.compile(
    r"(coupon|voucher|promo|discount|kupon|kode|redeem)",
    re.I,
)

# Daftar generic / debug code yang sering tertinggal di staging
COMMON_TEST_CODES = [
    "TEST", "TEST123", "DEMO", "ADMIN", "DEBUG",
    "FREE", "FREE100", "WELCOME", "WELCOME10",
    "PROMO", "DISKON", "DISKON50", "GRATIS",
    "DEV", "STAGING", "INTERNAL",
]
SUCCESS_HINTS = (
    "discount applied", "kode berhasil", "kupon diterapkan",
    "promo applied", "voucher applied", "successfully redeemed",
    "discount of", "potongan", "berhasil ditambahkan",
)


def _voucher_endpoints(target: Target, config: ScanConfig) -> list[str]:
    state = get_state(config)
    out = set()
    if state:
        for u in state.urls + state.param_urls:
            low = u.lower()
            if any(h in low for h in ("voucher", "coupon", "promo", "redeem", "kupon")):
                out.add(u)
    # Tambahkan common path
    for path in ("/api/voucher", "/api/coupon", "/api/promo/redeem", "/voucher/check"):
        out.add(urljoin(target.origin + "/", path))
    return list(out)[:10]


def _voucher_forms(config: ScanConfig) -> list[dict]:
    state = get_state(config)
    if not state:
        return []
    out: list[dict] = []
    for form in state.forms:
        for i in form["inputs"]:
            if VOUCHER_FIELDS.search(i.get("name", "") or ""):
                out.append(form)
                break
    return out


def _try_codes(client: HttpClient, form: dict) -> list[tuple[str, str]]:
    """Submit `COMMON_TEST_CODES` ke form voucher; kembalikan (code, evidence) jika sukses."""
    hits: list[tuple[str, str]] = []
    voucher_field = next(
        (i for i in form["inputs"] if VOUCHER_FIELDS.search(i.get("name", "") or "")),
        None,
    )
    if not voucher_field:
        return hits
    other_data = {
        i["name"]: (i.get("value") or "x")
        for i in form["inputs"]
        if i is not voucher_field and i.get("type") not in ("submit", "button")
    }
    for code in COMMON_TEST_CODES:
        data = {**other_data, voucher_field["name"]: code}
        if form.get("method", "get").lower() == "post":
            r = client.post(form["action"], data=data)
        else:
            r = client.get(form["action"], params=data)
        if r is None or r.status_code >= 500:
            continue
        body = (r.text or "").lower()
        if any(s in body for s in SUCCESS_HINTS):
            hits.append((code, f"status={r.status_code}, hint=success in body"))
            if len(hits) >= 3:
                break
    return hits


def _stack_abuse(client: HttpClient, form: dict) -> Finding | None:
    """Coba apply 2 kode berbeda berurutan: jika keduanya tetap diterima, indikasi stack abuse."""
    codes_to_try = ["WELCOME10", "DISKON50"]
    field = next(
        (i for i in form["inputs"] if VOUCHER_FIELDS.search(i.get("name", "") or "")),
        None,
    )
    if not field:
        return None
    other = {
        i["name"]: (i.get("value") or "x")
        for i in form["inputs"]
        if i is not field and i.get("type") not in ("submit", "button")
    }
    accepted = 0
    for code in codes_to_try:
        data = {**other, field["name"]: code}
        if form.get("method", "get").lower() == "post":
            r = client.post(form["action"], data=data)
        else:
            r = client.get(form["action"], params=data)
        if r is None:
            return None
        body = (r.text or "").lower()
        if any(s in body for s in SUCCESS_HINTS):
            accepted += 1
    if accepted >= 2:
        return Finding(
            module="voucher",
            title="Endpoint voucher kemungkinan menerima multiple kode berturut",
            severity=Severity.MEDIUM,
            description=(
                "Dua kode promo berbeda berturut-turut dilaporkan berhasil. Periksa "
                "apakah aplikasi memvalidasi 'satu voucher per transaksi' atau "
                "membolehkan stack diskon di sisi server."
            ),
            target=form.get("action", ""),
            evidence=f"codes_accepted={codes_to_try}",
            cwe="CWE-840",
            confidence="tentative",
            remediation=(
                "Validasi di sisi server: hanya satu voucher aktif per cart, batasi "
                "kombinasi diskon, dan jangan andalkan UI untuk mengunci field."
            ),
        )
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        forms = _voucher_forms(config)
        for form in forms[:5]:
            hits = _try_codes(client, form)
            for code, ev in hits:
                findings.append(
                    Finding(
                        module="voucher",
                        title=f"Kode voucher tebakan/test diterima: `{code}`",
                        severity=Severity.HIGH,
                        description=(
                            "Form voucher menerima kode generik/staging. Ini sering "
                            "tertinggal dari development atau menandakan tidak ada "
                            "rate-limit/whitelist pada redeem."
                        ),
                        target=form.get("action", ""),
                        evidence=ev,
                        cwe="CWE-521",
                        confidence="tentative",
                        remediation=(
                            "Hapus kode debug/staging di produksi. Terapkan rate-limit "
                            "per-IP/akun untuk endpoint redeem, dan log usaha gagal."
                        ),
                    )
                )
            stack = _stack_abuse(client, form)
            if stack:
                findings.append(stack)

        # Endpoint redeem yang menerima GET = potensi CSRF redeem
        for url in _voucher_endpoints(target, config):
            r = client.get(url)
            if r is None or r.status_code >= 400:
                continue
            ctype = r.headers.get("Content-Type", "").lower()
            if "json" in ctype or any(
                k in (r.text or "").lower() for k in ("voucher", "coupon", "redeem")
            ):
                findings.append(
                    Finding(
                        module="voucher",
                        title=f"Endpoint voucher dapat di-GET tanpa autentikasi: {url}",
                        severity=Severity.MEDIUM,
                        description=(
                            "Endpoint terkait voucher merespons GET dengan status 2xx "
                            "tanpa autentikasi. Berisiko di-enumerasi atau di-CSRF-kan."
                        ),
                        target=url,
                        evidence=f"HTTP {r.status_code}, content-type={ctype}",
                        cwe="CWE-352",
                        confidence="tentative",
                        remediation=(
                            "Lindungi endpoint redeem dengan autentikasi sesi + CSRF "
                            "token, gunakan POST, dan rate-limit per akun."
                        ),
                    )
                )
    finally:
        client.close()
    return findings
