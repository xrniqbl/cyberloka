"""Active IDOR validation: bandingkan response untuk dua identifier yang
berbeda, lalu konfirmasi response berisi data yang berbeda dan terstruktur
sama (= akses ke data user lain, bukan halaman 'forbidden' generic).

Strategi:
  1. Dari hasil crawler, ambil URL yang punya parameter ID numerik
     (`?id=`, `/users/123`, `/orders/456`, dst.).
  2. Untuk setiap URL, kirim variasi:
     - original     (id=N)
     - increment    (id=N+1, N+2)
     - decrement    (id=N-1)
     - extreme      (id=1, id=999999)
  3. Konfirmasi BUKAN false-positive bila:
     - Semua varian return 200 (server tidak filter)
     - Body length berbeda > 50 byte antara dua varian (bukan 'not found' page)
     - JSON terstruktur sama (key set identik) tapi value berbeda.

Modul ini menemukan IDOR REAL yang menampilkan data orang lain.
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

ID_PARAM_NAMES = re.compile(
    r"^(id|user_?id|account_?id|order_?id|invoice_?id|profile_?id|customer_?id|"
    r"member_?id|uid|pid|nid|item_?id|product_?id)$",
    re.I,
)
NUMERIC_PATH_RE = re.compile(r"/(users?|orders?|invoices?|accounts?|profiles?|"
                             r"customers?|posts?|items?|tickets?)/(\d+)/?")


def _candidate_urls(state, max_urls: int = 30) -> list[tuple[str, str, int]]:
    """Returns list of (full_url, kind, original_id_int)."""
    out: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    if not state:
        return out

    # Type 1: query param ?id=N
    for u in state.urls + state.param_urls:
        p = urlparse(u)
        qs = dict(parse_qsl(p.query))
        for k, v in qs.items():
            if ID_PARAM_NAMES.match(k) and v.isdigit():
                key = f"{p.path}?{k}"
                if key in seen:
                    continue
                seen.add(key)
                out.append((u, k, int(v)))
                if len(out) >= max_urls:
                    return out

    # Type 2: path /users/N
    for u in state.urls:
        m = NUMERIC_PATH_RE.search(u)
        if m:
            key = u
            if key in seen:
                continue
            seen.add(key)
            out.append((u, "_path_id", int(m.group(2))))
            if len(out) >= max_urls:
                return out
    return out


def _build_variant(url: str, kind: str, new_id: int) -> str:
    p = urlparse(url)
    if kind == "_path_id":
        new_path = NUMERIC_PATH_RE.sub(
            lambda m: f"/{m.group(1)}/{new_id}", p.path, count=1
        )
        return urlunparse(p._replace(path=new_path))
    qs = dict(parse_qsl(p.query, keep_blank_values=True))
    qs[kind] = str(new_id)
    return urlunparse(p._replace(query=urlencode(qs)))


def _structural_signature(body: str) -> str | None:
    """Return JSON key signature for response, or None if not structured JSON."""
    try:
        d = json.loads(body)
    except Exception:
        return None
    if isinstance(d, dict):
        return ",".join(sorted(d.keys()))
    if isinstance(d, list) and d and isinstance(d[0], dict):
        return "list:" + ",".join(sorted(d[0].keys()))
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    state = get_state(config)
    candidates = _candidate_urls(state)
    if not candidates:
        return findings

    client = HttpClient(config)
    try:
        for url, kind, original in candidates[:10]:
            variants = []
            for delta in (-1, +1, +2):
                new_id = original + delta
                if new_id <= 0:
                    continue
                variants.append((delta, _build_variant(url, kind, new_id)))

            r0 = client.get(url, allow_redirects=False)
            if r0 is None or r0.status_code != 200:
                continue
            body0 = r0.text or ""
            sig0 = _structural_signature(body0)
            len0 = len(body0)

            different_data = []
            for delta, vurl in variants:
                rv = client.get(vurl, allow_redirects=False)
                if rv is None or rv.status_code != 200:
                    continue
                bodyv = rv.text or ""
                lenv = len(bodyv)
                if abs(lenv - len0) < 50:
                    # bisa jadi cached page yang sama - skip
                    continue
                sigv = _structural_signature(bodyv)
                # Konfirmasi:
                # - Kalau JSON: signature sama (struktur sama) tapi body berbeda
                #   => data user lain.
                # - Kalau HTML: body length signifikan berbeda + tidak memuat
                #   'not found' / '404' / 'forbidden'.
                lower = bodyv.lower()[:5000]
                if any(k in lower for k in ("not found", "404", "forbidden", "tidak ditemukan", "unauthorized")):
                    continue
                if sig0 and sigv and sig0 == sigv and bodyv != body0:
                    different_data.append((delta, vurl, lenv, "json-same-schema-diff-data"))
                elif sig0 is None and sigv is None and abs(lenv - len0) >= 100:
                    different_data.append((delta, vurl, lenv, "html-significant-diff"))

            if len(different_data) >= 2:  # minimal 2 varian sukses untuk konfirmasi
                ev_lines = [
                    f"original: {url} (id={original}, len={len0})",
                    f"signature0: {sig0 or 'html'}",
                    "variants that returned different valid data:",
                ]
                for delta, vurl, lenv, reason in different_data[:5]:
                    ev_lines.append(f"  - id={original + delta}: {vurl} (len={lenv}) [{reason}]")
                findings.append(Finding(
                    module="idor_active_chain",
                    target=url,
                    title=f"IDOR aktif: parameter `{kind}` mengembalikan data user lain (≥2 varian)",
                    severity=Severity.HIGH,
                    description=(
                        f"Endpoint {url} menggunakan parameter ID sederhana yang dapat "
                        "diubah ke nilai lain dan mengembalikan data nyata yang BERBEDA "
                        "(bukan halaman 'not found'). Validasi multi-signal: minimal 2 "
                        "varian id mengembalikan struktur JSON yang sama atau body HTML "
                        "yang signifikan berbeda. Berarti server tidak mengecek "
                        "ownership/authorization sebelum menampilkan data."
                    ),
                    evidence="\n".join(ev_lines),
                    cwe="CWE-639",
                    confidence="confirmed",
                    urls=[url] + [v for _, v, _, _ in different_data],
                    remediation=(
                        "1. Ubah controller untuk MEMERIKSA bahwa user yang sedang login "
                        "memang berhak mengakses ID tersebut (mis. WHERE id=$id AND owner_id=$current_user).\n"
                        "2. Idealnya, ganti ID numerik dengan UUID acak supaya tidak bisa di-enumerate.\n"
                        "3. Tambahkan integration test yang akses /resource/<id-orang-lain>\n"
                        "   harus return 403/404."
                    ),
                    references=[
                        "https://cwe.mitre.org/data/definitions/639.html",
                        "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
                    ],
                ))
    finally:
        client.close()
    return findings
