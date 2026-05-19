"""Voucher / kupon abuse checks — strict-validation v0.10.4.

Sebelumnya: kalau body memuat ``discount applied`` setelah kirim kode,
flag sukses. Banyak halaman selalu menampilkan label discount sehingga
FP tinggi.

Sekarang konfirmasi:
- Baseline: kirim kode pasti-invalid (random gibberish). Body baseline
  tidak boleh memuat success hint.
- Test: kirim kode tebakan (TEST/DEMO/dll). Hanya konfirmasi kalau
  success hint muncul di test TAPI tidak di baseline DAN body berbeda
  signifikan dari baseline.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    body_similarity,
    build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

VOUCHER_FIELDS = re.compile(
    r"(coupon|voucher|promo|discount|kupon|kode|redeem)",
    re.I,
)

COMMON_TEST_CODES = [
    "TEST", "TEST123", "DEMO", "ADMIN", "DEBUG",
    "FREE", "FREE100", "WELCOME", "WELCOME10",
    "PROMO", "DISKON", "DISKON50", "GRATIS",
    "DEV", "STAGING", "INTERNAL",
]
SUCCESS_HINTS = (
    "discount applied", "kode berhasil", "kupon diterapkan",
    "promo applied", "voucher applied", "successfully redeemed",
    "discount of", "potongan diberikan",
)


def _voucher_endpoints(target: Target, config: ScanConfig) -> list[str]:
    state = get_state(config)
    out: set[str] = set()
    if state:
        for u in state.urls + state.param_urls:
            low = u.lower()
            if any(h in low for h in ("voucher", "coupon", "promo", "redeem", "kupon")):
                out.add(u)
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


def _submit(client: HttpClient, form: dict, voucher_field: dict, code: str):
    other = {
        i["name"]: (i.get("value") or "x")
        for i in form["inputs"]
        if i is not voucher_field and i.get("type") not in ("submit", "button")
    }
    data = {**other, voucher_field["name"]: code}
    if form.get("method", "get").lower() == "post":
        return client.post(form["action"], data=data)
    return client.get(form["action"], params=data)


def _try_codes(client: HttpClient, form: dict) -> list[tuple[str, str, ValidationProof]]:
    """Return list of (code, evidence, proof) — yang sudah lewat baseline check."""
    hits: list[tuple[str, str, ValidationProof]] = []
    voucher_field = next(
        (i for i in form["inputs"]
         if VOUCHER_FIELDS.search(i.get("name", "") or "")),
        None,
    )
    if not voucher_field:
        return hits

    bogus = f"CYBR{secrets.token_hex(6).upper()}"
    base = _submit(client, form, voucher_field, bogus)
    if base is None or base.status_code >= 500:
        return hits
    base_body = (base.text or "").lower()
    if any(s in base_body for s in SUCCESS_HINTS):
        return hits

    for code in COMMON_TEST_CODES:
        r = _submit(client, form, voucher_field, code)
        if r is None or r.status_code >= 500:
            continue
        body = (r.text or "").lower()
        if not any(s in body for s in SUCCESS_HINTS):
            continue
        sim = body_similarity(base_body, body)
        if sim > 0.92:
            continue
        proof = ValidationProof(
            method="random-bogus-baseline+similarity-diff",
            confirmed=True,
            steps=[
                f"Baseline kode random `{bogus}` -> response TIDAK memuat success hint.",
                f"Probe kode `{code}` -> response MEMUAT success hint, "
                f"sim(base, probe)={sim:.2f} (< 0.92).",
            ],
            samples=[f"code={code}, sim={sim:.2f}"],
        )
        hits.append((
            code,
            f"status={r.status_code}, sim(bogus_baseline, probe)={sim:.2f}",
            proof,
        ))
        if len(hits) >= 3:
            break
    return hits


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        forms = _voucher_forms(config)
        for form in forms[:5]:
            for code, ev, proof in _try_codes(client, form):
                findings.append(Finding(
                    module="voucher",
                    title=f"Kode voucher tebakan diterima setelah baseline-diff: `{code}`",
                    severity=Severity.HIGH,
                    description=(
                        "Form voucher menolak kode acak tapi menerima kode generik/"
                        "staging. Konfirmasi: response berbeda signifikan dari respons "
                        "kode invalid, dan memuat hint sukses voucher."
                    ),
                    target=form.get("action", ""),
                    evidence=ev,
                    cwe="CWE-521",
                    confidence="confirmed",
                    urls=[form.get("action", "")],
                    remediation=(
                        "Hapus kode debug/staging di produksi. Terapkan rate-limit "
                        "per-IP/akun untuk endpoint redeem, dan log usaha gagal."
                    ),
                    extra=build_extra(proof=proof),
                ))

        for url in _voucher_endpoints(target, config):
            r = client.get(url)
            if r is None or r.status_code >= 400:
                continue
            ctype = r.headers.get("Content-Type", "").lower()
            text_low = (r.text or "").lower()
            if "json" in ctype and any(
                k in text_low for k in ("voucher", "coupon", "redeem")
            ):
                findings.append(Finding(
                    module="voucher",
                    title=f"Endpoint voucher GET-able tanpa auth: {url}",
                    severity=Severity.MEDIUM,
                    description=(
                        "Endpoint terkait voucher merespons GET dengan status 2xx + "
                        "JSON yang menyebut voucher/coupon/redeem. Berisiko enumerasi "
                        "atau CSRF redeem."
                    ),
                    target=url,
                    evidence=f"HTTP {r.status_code}, content-type={ctype}",
                    cwe="CWE-352",
                    confidence="tentative",
                    remediation=(
                        "Lindungi endpoint redeem dengan autentikasi sesi + CSRF "
                        "token, gunakan POST, dan rate-limit per akun."
                    ),
                ))
    finally:
        client.close()
    return findings
