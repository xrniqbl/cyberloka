"""Server-Side Template Injection probe — strict-validation v0.10.4.

Penyempurnaan untuk menghilangkan false positive dari scanner versi lama
yang flag setiap response yang memuat angka ``49`` (dari ``7*7``):

1. Pakai DUA bilangan acak besar (113..9973) — produknya 4-7 digit dan
   sangat tidak mungkin muncul kebetulan.
2. Cek baseline (URL biasa) — kalau hasil perkalian sudah muncul di
   baseline, oracle tidak valid.
3. Wajibkan tiga syarat di response payload:
   - hasil perkalian muncul dengan **digit-boundary** (bukan substring),
   - payload mentah ``{{a*b}}`` TIDAK ikut tampil (artinya benar dievaluasi),
   - payload TIDAK juga muncul dalam bentuk ter-encode.
4. Konfirmasi ulang dengan operasi BERBEDA (penjumlahan + bilangan acak
   baru). Hanya kalau dua-duanya lolos, finding dilaporkan ``confirmed``.
"""
from __future__ import annotations

from cyberloka.active._helpers import append_param, candidate_urls, iter_param_urls
from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
    confirm_unique_arithmetic,
    random_arith_pair,
)
from cyberloka.core.config import ScanConfig

# Templating syntax — engine-agnostic (Jinja2/Twig/Liquid/Velocity/SpEL/ERB/Pug).
TEMPLATES_MUL = (
    "{{{{{a}*{b}}}}}",   # Jinja2 / Twig / Liquid
    "${{{{{a}*{b}}}}}",  # Velocity / Spring SpEL
    "<%= {a}*{b} %>",    # ERB
    "#{{{{{a}*{b}}}}}",  # Pug / Ruby
)
TEMPLATES_ADD = (
    "{{{{{a}+{b}}}}}",
    "${{{{{a}+{b}}}}}",
    "<%= {a}+{b} %>",
    "#{{{{{a}+{b}}}}}",
)


def _format(tpl: str, a: int, b: int) -> str:
    # Manual substitution: format() bingung dengan ``{{ }}`` literal.
    return tpl.replace("{a}", str(a)).replace("{b}", str(b))


def _scan_url(client, url):
    findings: list[Finding] = []
    if True:
        baseline = client.get(url)
        baseline_body = (baseline.text or "") if baseline is not None else ""

        for tpl_mul, tpl_add in zip(TEMPLATES_MUL, TEMPLATES_ADD):
            a, b, prod = random_arith_pair()
            payload_mul = _format(tpl_mul, a, b)
            # Jangan trust angka yang sudah muncul di baseline.
            if str(prod) in baseline_body:
                continue

            for param, mutated in iter_param_urls(url, payload_mul):
                r = client.get(mutated)
                if r is None:
                    continue
                body = r.text or ""
                if not confirm_unique_arithmetic(
                    body=body, expected=prod, payload=payload_mul
                ):
                    continue

                # Konfirmasi kedua: operasi BERBEDA dengan bilangan acak baru.
                a2, b2, _ = random_arith_pair()
                summ = a2 + b2
                if str(summ) in baseline_body:
                    continue
                payload_add = _format(tpl_add, a2, b2)
                mutated2 = next(
                    (u for p, u in iter_param_urls(url, payload_add) if p == param),
                    None,
                )
                if not mutated2:
                    continue
                r2 = client.get(mutated2)
                if r2 is None:
                    continue
                if not confirm_unique_arithmetic(
                    body=r2.text or "", expected=summ, payload=payload_add
                ):
                    continue

                proof = ValidationProof(
                    method="random-arith+double-confirm",
                    confirmed=True,
                    steps=[
                        f"Baseline body TIDAK memuat angka {prod} maupun {summ}.",
                        f"Payload mul `{payload_mul}` -> response memuat {prod} "
                        f"(digit-boundary), payload mentah TIDAK terlihat.",
                        f"Payload add `{payload_add}` -> response memuat {summ} "
                        f"(digit-boundary), payload mentah TIDAK terlihat.",
                        "Dua operasi independen dievaluasi server-side -> SSTI nyata.",
                    ],
                    samples=[f"mul={a}*{b}={prod}", f"add={a2}+{b2}={summ}"],
                )
                findings.append(
                    Finding(
                        module="ssti",
                        title=f"Server-Side Template Injection terkonfirmasi pada `{param}`",
                        severity=Severity.CRITICAL,
                        description=(
                            "Dua payload template independen (perkalian + penjumlahan "
                            "dengan bilangan acak) dievaluasi oleh server. Pola ini "
                            "praktis tidak mungkin terjadi kebetulan, sehingga "
                            "konfirmasi SSTI sangat kuat. SSTI berpotensi RCE."
                        ),
                        target=mutated,
                        evidence=(
                            f"mul: {payload_mul} -> {prod} muncul; "
                            f"add: {payload_add} -> {summ} muncul"
                        ),
                        cwe="CWE-94",
                        confidence="confirmed",
                        urls=[mutated, mutated2],
                        remediation=(
                            "Jangan render input user lewat template engine. Gunakan "
                            "engine auto-escape, jalankan template di sandbox, dan "
                            "filter karakter kontrol template (`{{`, `}}`, `${`, `%>`)."
                        ),
                        extra=build_extra(proof=proof),
                    )
                )
                return findings
    return findings


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    seen_paths: set[str] = set()
    try:
        from urllib.parse import urlparse
        for url in candidate_urls(target, config, fallback_param="q", fallback_value="test"):
            path = urlparse(url).path
            if path in seen_paths:
                continue
            for f in _scan_url(client, url):
                seen_paths.add(path)
                findings.append(f)
    finally:
        client.close()
    return findings
