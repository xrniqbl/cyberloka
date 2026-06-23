"""Form-aware fuzzer — strict-validation v0.10.7.

Versi lama melaporkan XSS/SQLi via form hanya dari sinyal lemah:
  * "payload terpantul di body" -> XSS (padahal bisa ter-escape / di konteks
    non-eksekutif / di-echo apa pun).
  * "ada kata `mysql`/`sql syntax` di body" -> SQLi (padahal halaman error
    generik bisa memuat kata itu).
Itu berlawanan dengan filosofi strict-validation modul lain dan jadi sumber
false-positive.

Sekarang setiap finding form WAJIB lolos validasi:

XSS via form:
  1. Submit token acak benign -> harus DIPANTULKAN (server reflektif).
  2. Submit payload `<sCript>...tokenA</sCript>` -> dipantulkan UTUH (tidak
     ter-escape) DAN tidak di konteks non-eksekutif (textarea/title/comment).
  3. Double-confirm dengan tokenB berbeda -> juga dipantulkan utuh.
  4. Content-Type response text/html.

SQLi via form (error-based):
  1. Submit nilai benign -> response TIDAK memuat signature DB-error.
  2. Submit payload quote -> response MEMUAT signature DB-error.
  -> error hanya muncul setelah payload, bukan halaman error generik.
"""
from __future__ import annotations

import re
import secrets
from html import escape as html_escape

from cyberloka.active._helpers import (
    build_form_data,
    candidate_forms,
    form_fuzz_fields,
    submit_form,
)
from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# DB error signatures (sama dengan modul sqli untuk konsistensi).
SQLI_ERROR_RE = re.compile(
    "|".join([
        r"sql syntax.*mysql",
        r"warning.*mysql",
        r"valid mysql result",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"sqlstate\[",
        r"odbc.*sql server",
        r"microsoft sql native client",
        r"pg::syntaxerror",
        r"postgresql.*error",
        r"sqlite3?::",
        r"oracle.*ora-\d{4,}",
        r"you have an error in your sql syntax",
    ]),
    re.I,
)

# Konteks HTML non-eksekutif (token di dalamnya bukan XSS).
NON_EXEC_OPEN_RE = re.compile(
    r"<(textarea|title|pre|noscript|style|script|xmp|plaintext)\b[^>]*>", re.I
)


def _is_non_exec(body: str, idx: int) -> bool:
    pre = body[:idx]
    last = None
    for m in NON_EXEC_OPEN_RE.finditer(pre):
        last = m
    if last is not None:
        tag = last.group(1).lower()
        if not re.compile(rf"</{tag}\b", re.I).search(pre, last.end()):
            return True
    c = pre.rfind("<!--")
    if c != -1 and pre.find("-->", c + 4) == -1:
        return True
    return False


def _tok(p: str) -> str:
    return f"{p}{secrets.token_hex(4)}"


def _check_xss(client: HttpClient, form: dict, field: str) -> ValidationProof | None:
    # 1) reflektif?
    benign = _tok("base")
    r0 = submit_form(client, form, build_form_data(form, field, benign))
    if r0 is None or "html" not in r0.headers.get("Content-Type", "").lower():
        return None
    if benign not in (r0.text or ""):
        return None  # tidak reflektif

    # 2) payload utama
    t1 = _tok("cybA")
    p1 = f"<sCript>cyberloka{t1}</sCript>"
    r1 = submit_form(client, form, build_form_data(form, field, p1))
    if r1 is None:
        return None
    b1 = r1.text or ""
    if p1 not in b1:
        # ter-escape => aman
        return None
    idx = b1.find(p1)
    if _is_non_exec(b1, idx):
        return None
    window = b1[max(0, idx - 4): idx + len(p1) + 4]
    if "&lt;" in window and "<" not in window.replace("&lt;", ""):
        return None

    # 3) double-confirm token berbeda
    t2 = _tok("cybB")
    p2 = f"<sCript>cyberloka{t2}</sCript>"
    r2 = submit_form(client, form, build_form_data(form, field, p2))
    if r2 is None or p2 not in (r2.text or ""):
        return None
    if _is_non_exec(r2.text or "", (r2.text or "").find(p2)):
        return None

    return ValidationProof(
        method="form-reflect+context+double-confirm",
        confirmed=True,
        steps=[
            f"Submit token benign `{benign}` ke field `{field}` -> dipantulkan (reflektif).",
            f"Payload-1 `{p1}` dipantulkan UTUH (tidak ter-escape) di konteks eksekutif.",
            f"Payload-2 `{p2}` (token beda) JUGA dipantulkan utuh -> konsisten.",
        ],
        samples=[truncate(window, 200)],
    )


def _check_sqli(client: HttpClient, form: dict, field: str) -> ValidationProof | None:
    # 1) baseline benign harus bersih dari error DB
    benign = "cyberloka1"
    r0 = submit_form(client, form, build_form_data(form, field, benign))
    if r0 is not None and SQLI_ERROR_RE.search(r0.text or ""):
        return None  # halaman sudah memuat error generik -> tidak reliable

    # 2) payload quote memunculkan signature
    r1 = submit_form(client, form, build_form_data(form, field, "1'\""))
    if r1 is None:
        return None
    m = SQLI_ERROR_RE.search(r1.text or "")
    if not m:
        return None
    sig = truncate(m.group(0), 120)
    return ValidationProof(
        method="form-error-based+benign-control",
        confirmed=True,
        steps=[
            f"Submit nilai benign ke field `{field}` -> TIDAK ada signature DB-error.",
            f"Submit quote payload -> response memuat signature DB-error: `{sig}`.",
        ],
        samples=[sig],
    )


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for form in candidate_forms(config):
            action = form.get("action")
            if not action:
                continue
            fields = form_fuzz_fields(form)
            if not fields:
                continue

            # XSS: cukup satu field terbukti per form.
            for field in fields:
                proof = _check_xss(client, form, field)
                if proof:
                    findings.append(Finding(
                        module="forms",
                        title=f"Reflected XSS via form `{action}` (field `{field}`, terkonfirmasi)",
                        severity=Severity.HIGH,
                        description=(
                            "Form mengembalikan input pengguna ke halaman tanpa encoding "
                            "yang aman, di konteks HTML eksekutif, dikonfirmasi dua token "
                            "berbeda."
                        ),
                        target=action,
                        evidence=proof.samples[0] if proof.samples else "",
                        cwe="CWE-79",
                        confidence="confirmed",
                        urls=[action],
                        remediation="Output encoding kontekstual + CSP ketat. Auto-escape template.",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                        ],
                        extra=build_extra(proof=proof),
                    ))
                    break

            # SQLi: cukup satu field terbukti per form.
            for field in fields:
                proof = _check_sqli(client, form, field)
                if proof:
                    findings.append(Finding(
                        module="forms",
                        title=f"SQL Injection via form `{action}` (field `{field}`, error-based)",
                        severity=Severity.CRITICAL,
                        description=(
                            "Form memunculkan error database setelah disuntik karakter quote "
                            "sementara submit benign tidak memunculkan error -> indikasi kuat SQLi."
                        ),
                        target=action,
                        evidence=proof.samples[0] if proof.samples else "",
                        cwe="CWE-89",
                        confidence="confirmed",
                        urls=[action],
                        remediation="Gunakan parameterized queries / prepared statements.",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                        ],
                        extra=build_extra(proof=proof),
                    ))
                    break
    finally:
        client.close()
    return findings
