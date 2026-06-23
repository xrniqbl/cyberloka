"""Reflected XSS detection — strict-validation v0.10.3.

Masalah lama: scanner suka laporkan "200 + marker echo" sebagai XSS HIGH,
padahal sebenarnya:
  * Halaman search hanya menampilkan kata pencarian (HTML-escaped) -> AMAN.
  * 404 / SPA-shell yang echo raw param di JSON / atribut data-* -> AMAN.
  * Server selalu balas body yang sama -> bukan reflektif.

Solusi: 5 lapis validasi sebelum berani LAPORKAN.

Lapisan:
  1. Negative-control fetch: param yang sama dengan TOKEN A acak harus
     dipantulkan; bila TIDAK dipantulkan, server tidak reflektif -> SKIP.
  2. Konteks executable: hit harus berada di konteks HTML/attr/JS-string
     yang BISA dieksekusi browser. Kalau token berada di dalam:
        - <textarea>...</textarea>
        - <title>...</title>
        - <pre>...</pre>
        - <noscript>...</noscript>
        - HTML comment <!-- ... -->
        - Konten yang Content-Type bukan text/html
     -> SKIP (bukan XSS).
  3. Raw-reflection check: response harus memuat karakter `<` / `>` /
     `"` (sesuai konteks payload) dalam keadaan TIDAK ter-encode (tidak
     ada `&lt;`/`&gt;`/`&quot;` yang menggantikan). Kalau body memuat
     versi ter-encode dari payload -> server escape -> SKIP.
  4. Double-confirm: kirim token kedua (BERBEDA) dengan struktur sama.
     Harus sama-sama dipantulkan raw. Ini menutup celah di mana hit
     pertama hanya kebetulan (mis. token nyangkut di response cache).
  5. Sanity baseline: request URL tanpa parameter (atau param=baseline)
     TIDAK boleh memuat token kita. Kalau iya -> server echo sembarang
     string -> SKIP.

Hanya finding yang LULUS 5 lapis ini yang dilaporkan dengan severity HIGH
dan confidence='confirmed'. Selebihnya tidak dilaporkan.
"""
from __future__ import annotations

import re
import secrets
from html import escape as html_escape

from cyberloka.active._helpers import append_param, candidate_urls, iter_param_urls
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
from cyberloka.reporting.awam import get_awam

# Daerah HTML yang TIDAK eksekutif (token di dalam ini bukan XSS).
NON_EXEC_OPEN_RE = re.compile(
    r"<(textarea|title|pre|noscript|style|script|xmp|plaintext)\b[^>]*>",
    re.I,
)
HTML_COMMENT_OPEN = "<!--"


def _is_in_non_exec_context(body: str, idx: int) -> tuple[bool, str]:
    """Cek apakah index `idx` berada di dalam textarea/title/comment/dst.

    Algoritma sederhana: scan backward dari `idx` dan cari tag pembuka
    yang BELUM ditutup. Kalau yang terakhir adalah salah satu non-exec,
    konteksnya bukan eksekutif.
    """
    pre = body[:idx]
    last_open = None
    for m in NON_EXEC_OPEN_RE.finditer(pre):
        last_open = m
    if last_open is not None:
        tag = last_open.group(1).lower()
        close_re = re.compile(rf"</{tag}\b", re.I)
        m2 = close_re.search(pre, last_open.end())
        if not m2:
            return True, f"di dalam <{tag}>"
    last_comment = pre.rfind(HTML_COMMENT_OPEN)
    if last_comment != -1:
        end_comment = pre.find("-->", last_comment + 4)
        if end_comment == -1:
            return True, "di dalam HTML comment"
    return False, ""


def _make_token(prefix: str) -> str:
    return f"{prefix}{secrets.token_hex(4)}"


def _scan_url(client, url, awam_summary, awam_steps):
    findings: list[Finding] = []
    if True:
        # ==== Step 0: baseline (URL tanpa value sensitive) ====
        baseline_token = _make_token("base")
        baseline_url = next(
            (u for _, u in iter_param_urls(url, baseline_token)),
            None,
        )
        if baseline_url is None:
            return findings
        baseline_resp = client.get(baseline_url)
        if baseline_resp is None:
            return findings
        baseline_body = baseline_resp.text or ""
        baseline_ctype = baseline_resp.headers.get("Content-Type", "").lower()
        if "html" not in baseline_ctype:
            return findings  # Bukan halaman HTML, skip XSS check.

        if baseline_token not in baseline_body:
            return findings  # Tidak reflektif sama sekali.

        # ==== Step 1: payload utama (token di konteks HTML body) ====
        token1 = _make_token("cybA")
        payload1 = f"<sCript>cyberloka{token1}</sCript>"
        for param, mutated in iter_param_urls(url, payload1):
            resp = client.get(mutated)
            if resp is None:
                continue
            body = resp.text or ""
            ctype = resp.headers.get("Content-Type", "").lower()
            if "html" not in ctype:
                continue

            if payload1 not in body:
                escaped = html_escape(payload1)
                if escaped in body:
                    continue  # Server escape -> AMAN.
                continue

            idx = body.find(payload1)

            non_exec, where = _is_in_non_exec_context(body, idx)
            if non_exec:
                continue

            window = body[max(0, idx - 4): idx + len(payload1) + 4]
            if "&lt;" in window and "<" not in window.replace("&lt;", ""):
                continue

            # Step 5: double-confirm dengan token KEDUA berbeda.
            token2 = _make_token("cybB")
            payload2 = f"<sCript>cyberloka{token2}</sCript>"
            mutated2 = next(
                (u for p, u in iter_param_urls(url, payload2) if p == param),
                None,
            )
            if not mutated2:
                continue
            resp2 = client.get(mutated2)
            if resp2 is None or payload2 not in (resp2.text or ""):
                continue
            body2 = resp2.text or ""
            non_exec2, _ = _is_in_non_exec_context(body2, body2.find(payload2))
            if non_exec2:
                continue

            # Step 6: anti-echo (baseline tidak boleh memuat payload eksak)
            if payload1 in baseline_body:
                continue

            snippet = truncate(body[max(0, idx - 80): idx + len(payload1) + 80], 240)
            proof = ValidationProof(
                method="reflect+context+double-confirm+anti-escape",
                confirmed=True,
                steps=[
                    f"Baseline pada `{param}={baseline_token}` -> token DIPANTULKAN raw.",
                    f"Payload-1 `{payload1}` dipantulkan utuh (tidak ter-escape) di response.",
                    f"Konteks: bukan textarea/title/pre/comment -> EKSEKUTIF.",
                    f"Tidak ditemukan versi `&lt;script&gt;...` (server tidak escape).",
                    f"Payload-2 `{payload2}` (token berbeda) JUGA dipantulkan utuh - reflektif konsisten.",
                    "Anti-echo: baseline body tidak mengandung payload spesifik kita.",
                ],
                samples=[snippet],
            )
            findings.append(
                Finding(
                    module="xss",
                    title=f"Reflected XSS pada parameter `{param}` (terkonfirmasi)",
                    severity=Severity.HIGH,
                    description=(
                        "Payload HTML/JS yang dikirim lewat parameter URL dipantulkan "
                        "utuh ke body response (tidak di-escape) DI KONTEKS EKSEKUTIF "
                        "HTML, dan dikonfirmasi ulang dengan token berbeda. "
                        "Terbuka untuk eksekusi script di browser korban."
                    ),
                    target=mutated,
                    evidence=snippet,
                    cwe="CWE-79",
                    confidence="confirmed",
                    urls=[mutated],
                    remediation=(
                        "Lakukan output encoding kontekstual (HTML entity encode untuk "
                        "konten HTML, JS-encode untuk konteks <script>, URL-encode untuk "
                        "atribut href). Gunakan template engine yang auto-escape (Jinja2 "
                        "auto-escape, React JSX). Tambahkan CSP yang ketat sebagai pertahanan."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ],
                    extra=build_extra(
                        proof=proof,
                        awam_steps=awam_steps,
                        awam_summary=awam_summary,
                    ),
                )
            )
            break
    return findings


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary, awam_steps = get_awam("xss")
    seen_points: set[tuple] = set()
    try:
        from urllib.parse import urlparse
        # Smart targeting: uji base_url + SEMUA endpoint berparameter hasil crawl.
        for url in candidate_urls(target, config, fallback_param="q", fallback_value="test"):
            path = urlparse(url).path
            for f in _scan_url(client, url, awam_summary, awam_steps):
                key = (path, f.title)
                if key in seen_points:
                    continue
                seen_points.add(key)
                findings.append(f)
    finally:
        client.close()
    return findings
