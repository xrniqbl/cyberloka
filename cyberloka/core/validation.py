"""Strict-validation helpers shared by all scanners.

Goal: setiap finding yang menyatakan "akses ke root", "baca file di server",
"akses database", "kebocoran PII", dst. WAJIB melalui validasi tambahan
sebelum di-laporkan agar laporan tidak banyak false-positive.

Design:
- :class:`ValidationProof` adalah dict-like struct yang ditempel ke
  ``Finding.extra["validation"]``. Reporter (PDF/HTML/JSON) akan menampilkan
  isinya kepada pembaca sebagai bukti audit-trail bahwa finding di-double-check.

- :func:`is_soft_200` mendeteksi response 200 yang sebenarnya halaman SPA /
  generic 404 (mis. Next.js, Nuxt, React Router) sehingga path "tidak ada"
  tidak salah dilaporkan sebagai file ter-ekspos.

- :func:`stable_baseline` mengirim 2 request "kontrol" tanpa payload untuk
  memastikan response tidak berubah-ubah (variabel) — agar boolean/IDOR
  detection tidak salah karena response normal sudah berbeda di tiap fetch.

- :func:`double_confirm` menjalankan ulang probe yang sukses dan menyatakan
  finding hanya bila hasil konsisten dua kali berturut-turut.

- :func:`body_similarity` menghitung kemiripan dua body (0..1) berbasis
  token Jaccard + length ratio. Dipakai untuk differential test (boolean
  SQLi, IDOR, business-logic).

- :func:`random_marker` & :func:`random_arith_pair` menghasilkan oracle
  acak agar SSTI/CMDi/XSS hanya laporkan kalau marker yang muncul di
  response benar-benar HASIL eksekusi (bukan kebetulan).

Bahasa Indonesia karena report end-user adalah engineer Indonesia.
"""
from __future__ import annotations

import random
import re
import secrets
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import requests

from cyberloka.core.http_client import HttpClient


# ---------------------------------------------------------------------------
# Validation proof object — attached to Finding.extra["validation"]
# ---------------------------------------------------------------------------


@dataclass
class ValidationProof:
    """Structured proof bahwa finding sudah di-validasi.

    Dipakai oleh modul scanner. Reporter akan merender isi-nya sebagai bukti
    bahwa finding tidak di-laporkan asal-asalan.
    """

    method: str
    """Singkat: "double-fetch", "marker-cross-check", "luhn", "soft-200-rejected", dll."""

    steps: list[str] = field(default_factory=list)
    """Langkah teknis yang dijalankan oleh scanner (audit trail)."""

    samples: list[str] = field(default_factory=list)
    """Cuplikan bukti (signature regex hit, snippet body) — sudah dipotong pendek."""

    confirmed: bool = False
    """True hanya bila SEMUA langkah validasi berhasil."""

    notes: str = ""
    """Catatan tambahan: misal soft-200, content-length konsisten, dll."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "confirmed": self.confirmed,
            "steps": list(self.steps),
            "samples": list(self.samples),
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Soft-200 detection
# ---------------------------------------------------------------------------

_SOFT_404_HINTS = (
    # Common framework "200 catch-all" pages
    "<div id=\"__next\"",
    "<div id=\"root\"",
    "<title>404",
    "page not found",
    "not found</title>",
    "halaman tidak ditemukan",
    "tidak dapat ditemukan",
    "this page could not be found",
    "<noscript>you need to enable javascript",
    # Cloudflare error
    "error code 1003",
    "<title>attention required",
)


def is_soft_200(resp: requests.Response | None) -> bool:
    """Return True bila response 200 sebenarnya halaman generic / SPA shell.

    Kriteria (heuristik konservatif):
      * Body kosong, atau
      * Body HTML pendek + kontainer SPA root tanpa konten lain, atau
      * Title/text mengandung 404/not-found.
    """
    if resp is None or resp.status_code != 200:
        return False
    body = (resp.text or "")
    if not body:
        return True
    low = body.lower()
    if any(h in low for h in _SOFT_404_HINTS):
        # SPA shell with no real content → treat as soft-200
        # (we accept this as "not actually a hit")
        return True
    return False


def catch_all_control(client: "HttpClient", base: str) -> str | None:
    """Ambil body dari path yang DIPASTIKAN tidak ada (kontrol negatif).

    Mengembalikan body bila server membalas 200 untuk path acak (artinya
    server "catch-all 200" / SPA fallback). Bila server membalas 4xx/3xx
    yang benar untuk path tak-ada, kembalikan ``None`` (tidak ada catch-all).

    Modul probe-path memakai ini untuk menolak temuan yang sebetulnya hanya
    halaman catch-all yang sama untuk URL apa pun (akar false-positive
    soft-404 SPA, mis. /administrator atau /.env yang balas beranda).
    """
    import secrets as _secrets
    from urllib.parse import urljoin as _urljoin

    url = _urljoin(base.rstrip("/") + "/", f"cyberloka_{_secrets.token_hex(6)}_nx")
    r = client.get(url, allow_redirects=False)
    if r is not None and r.status_code == 200 and (r.text or ""):
        return r.text or ""
    return None


def is_catch_all_response(
    body: str, control_body: str | None, threshold: float = 0.95
) -> bool:
    """True bila ``body`` pada dasarnya sama dengan body kontrol negatif.

    Dipakai bersama :func:`catch_all_control`. Bila skor kemiripan
    (``body_similarity``) >= threshold, response ini hanyalah halaman
    catch-all yang sama untuk URL apa pun → BUKAN temuan nyata.
    """
    if not control_body:
        return False
    return body_similarity(body or "", control_body) >= threshold


# ---------------------------------------------------------------------------
# Baseline stability + double confirmation
# ---------------------------------------------------------------------------


def stable_baseline(
    client: HttpClient,
    url: str,
    *,
    samples: int = 2,
    tolerance: int = 80,
) -> tuple[bool, int, int]:
    """Cek apakah response 200 untuk URL stabil panjangnya antara fetch berurutan.

    Mengembalikan ``(stable, length_min, length_max)``. Modul boolean / IDOR
    pakai ini sebelum simpulkan "panjang berbeda → vulnerable".
    """
    sizes: list[int] = []
    for _ in range(max(2, samples)):
        r = client.get(url)
        if r is None or r.status_code >= 400:
            return False, 0, 0
        sizes.append(len(r.text or ""))
    lo, hi = min(sizes), max(sizes)
    return (hi - lo) <= tolerance, lo, hi


def double_confirm(probe: Callable[[], bool]) -> bool:
    """Jalankan probe(), kalau True jalankan sekali lagi untuk memastikan."""
    if not probe():
        return False
    return probe()


# ---------------------------------------------------------------------------
# Body-shape filters (prevent reporting SPA HTML as a leaked file)
# ---------------------------------------------------------------------------


def looks_like_html_shell(body: str) -> bool:
    """True bila body terlihat seperti SPA/HTML generic, bukan file plain.

    Berguna untuk source_leak / sensitive_files: kalau /backup.sql atau /.env
    balas HTML SPA (catch-all 200), JANGAN dilaporkan sebagai "file bocor".

    Detektor diperkuat (v0.10.6): tidak lagi bergantung pada marker sempit
    ``<div id="__next">`` saja. Banyak app modern (Next.js App Router, Nuxt,
    Remix, Angular) tidak menulis marker itu sehingga dulu lolos dan memicu
    false-positive ``confirmed``. Sekarang kita kenali:
      * Pembuka dokumen HTML asli (`<!doctype html`, `<html`).
      * Marker hidrasi framework SPA (`/_next/`, `self.__next_f`, `__NUXT__`,
        `window.__remixContext`, `data-reactroot`, `ng-version`).
      * Heuristik generik: >=2 tag struktur HTML (`<head>`, `<body>`,
        `<meta>`, `<script>`, `<title>`, `<div>`).
    """
    if not body:
        return False
    head = body[:4096].lower()

    # 1) Pembuka dokumen HTML asli — sinyal kuat tunggal.
    if "<!doctype html" in head or "<html" in head:
        return True

    # 2) Marker hidrasi SPA meski <html> tidak ada di 4KB pertama.
    spa_markers = (
        "/_next/", "self.__next_f", "__next_data__",
        "__nuxt__", "window.__nuxt", "window.__remix", "data-reactroot",
        "ng-version", "<app-root", "id=\"__next\"", "id=\"root\"", "id=\"app\"",
    )
    if any(m in head for m in spa_markers):
        return True

    # 3) Heuristik generik: >=2 tag struktur HTML ⇒ ini halaman, bukan file.
    structural = ("<head", "<body", "<meta ", "<script", "<title>",
                  "<div", "<link ", "<style", "<noscript>")
    if sum(1 for m in structural if m in head) >= 2:
        return True

    return False


def content_type_is_text_data(content_type: str) -> bool:
    """True kalau Content-Type konsisten dengan file plain (bukan HTML).

    Dipakai untuk validasi env_leak / source_leak: file `.env` dan `.git/HEAD`
    seharusnya bukan ``text/html``.
    """
    ct = (content_type or "").lower()
    if not ct:
        return True  # banyak server tidak set CT untuk static file
    return any(part in ct for part in (
        "text/plain", "application/octet-stream", "application/json",
        "application/x-yaml", "application/yaml", "application/sql",
        "application/x-sh", "application/xml",
    ))


# ---------------------------------------------------------------------------
# Convenience: build extra dict for Finding
# ---------------------------------------------------------------------------


def build_extra(
    proof: ValidationProof | None = None,
    awam_steps: list[str] | None = None,
    awam_summary: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Bentuk dict standar untuk ``Finding.extra``.

    Reporter akan baca tiga key spesifik:
      * ``validation`` — bukti audit-trail teknis (ValidationProof.to_dict()).
      * ``awam_steps`` — langkah-langkah Bahasa Awam: cara akses ke celah ini
        dijelaskan step-by-step untuk pembaca non-teknis.
      * ``awam_summary`` — satu-paragraf rangkuman bahasa awam.
    """
    out: dict[str, Any] = dict(extra or {})
    if proof is not None:
        out["validation"] = proof.to_dict()
    if awam_steps:
        out["awam_steps"] = list(awam_steps)
    if awam_summary:
        out["awam_summary"] = awam_summary
    return out


# ---------------------------------------------------------------------------
# Body similarity (differential probing)
# ---------------------------------------------------------------------------


def body_similarity(a: str, b: str) -> float:
    """Approx similarity 0..1 antara dua body. Sederhana tapi cepat.

    Bobot:
    - Token overlap (Jaccard) sangat dominan; jika overlap = 0, similarity
      paling tinggi 0.33 walau panjang persis sama.
    - Length ratio sebagai tie-breaker.

    Dipakai untuk differential probing (boolean SQLi, IDOR, voucher,
    payment business-logic) di mana kita ingin membedakan respons "sama
    seperti baseline" vs "berbeda secara substansi".
    """
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    la, lb = len(a), len(b)
    sa = set(a.split())
    sb = set(b.split())
    if not sa or not sb:
        return 1.0 if a == b else 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    overlap = inter / union if union else 0.0
    len_ratio = 1 - abs(la - lb) / max(la, lb) if max(la, lb) else 1.0
    # Overlap bobot 2/3, length ratio 1/3.
    return (2 * overlap + len_ratio) / 3


# ---------------------------------------------------------------------------
# Random oracles (XSS / SSTI / CMDi / SSRF)
# ---------------------------------------------------------------------------


def random_marker(prefix: str = "cyberloka", n_bytes: int = 5) -> str:
    """Marker acak unik untuk membedakan reflection asli vs konten incidental.

    Dipakai untuk XSS / cache-poison / host-header / log-injection /
    cmdi marker test agar response yang sudah memuat string scanner
    tidak menyebabkan false positive.
    """
    return f"{prefix}{secrets.token_hex(n_bytes)}"


def random_arith_pair(
    *, min_factor: int = 113, max_factor: int = 9973
) -> tuple[int, int, int]:
    """Pasang dua bilangan kecil + hasil perkaliannya.

    Hasilnya 4-7 digit dan TIDAK trivial (mis. ``49`` dari ``7*7`` yang
    sering muncul sebagai item count / page number), sehingga jika
    muncul di response server hampir pasti karena dievaluasi.

    Dipakai oleh :mod:`cyberloka.active.ssti` sebagai oracle.
    """
    a = random.randint(min_factor, max_factor)
    b = random.randint(min_factor, max_factor)
    return a, b, a * b


def confirm_unique_arithmetic(
    *, body: str, expected: int, payload: str
) -> bool:
    """Konfirmasi SSTI: hasil perkalian muncul, payload mentah tidak.

    Plus syarat tambahan: ``expected`` harus muncul sebagai token utuh
    (digit-boundary) bukan substring dari angka lain.
    """
    if payload in body:
        return False  # template tidak dievaluasi, hanya dipantulkan
    pat = re.compile(rf"(?<!\d){expected}(?!\d)")
    return bool(pat.search(body))


# ---------------------------------------------------------------------------
# Time-based oracle (multi-sample timing)
# ---------------------------------------------------------------------------


def confirm_time_delay(
    client: HttpClient,
    *,
    method: str,
    fast_url: str,
    slow_url: str,
    expected_delay: float,
    samples: int = 3,
    fast_kwargs: dict | None = None,
    slow_kwargs: dict | None = None,
) -> tuple[bool, list[float], list[float]]:
    """Konfirmasi time-based injection dengan multi-sample.

    Mengukur baseline (fast) dan injeksi (slow) ``samples`` kali tiap-nya.
    Mengembalikan ``(confirmed, fast_times, slow_times)``. Konfirmasi
    bila:
    - ``median(slow) >= median(fast) + expected_delay * 0.85``
    - DAN ``min(slow) >= max(fast)`` (semua sampel slow lebih lambat dari
      semua sampel fast — menyingkirkan jitter network).
    """
    fast_kwargs = fast_kwargs or {}
    slow_kwargs = slow_kwargs or {}
    fast_times: list[float] = []
    slow_times: list[float] = []
    for _ in range(samples):
        t0 = time.monotonic()
        r = client.request(method, fast_url, **fast_kwargs)
        if r is not None:
            fast_times.append(time.monotonic() - t0)
    for _ in range(samples):
        t0 = time.monotonic()
        r = client.request(method, slow_url, **slow_kwargs)
        if r is not None:
            slow_times.append(time.monotonic() - t0)
    if len(fast_times) < 2 or len(slow_times) < 2:
        return False, fast_times, slow_times
    med_fast = statistics.median(fast_times)
    med_slow = statistics.median(slow_times)
    if med_slow < med_fast + expected_delay * 0.85:
        return False, fast_times, slow_times
    return min(slow_times) >= max(fast_times), fast_times, slow_times


def detect_timing_oracle(
    samples_a: list[float], samples_b: list[float],
    *, min_delta_ms: float = 200.0, min_samples: int = 8,
) -> tuple[bool, float, float]:
    """Statistical timing-side-channel detector.

    Dipakai oleh ``timing_attack`` untuk membedakan akun valid vs invalid.
    Mengembalikan ``(confirmed, delta_ms, t_score)``. Konfirmasi:
    - cukup banyak sampel (``>= min_samples`` per grup)
    - perbedaan median ``>= min_delta_ms``
    - ``|delta| > 3 * stdev_pooled`` (z-score signifikan)
    """
    if len(samples_a) < min_samples or len(samples_b) < min_samples:
        return False, 0.0, 0.0
    med_a = statistics.median(samples_a)
    med_b = statistics.median(samples_b)
    delta_ms = (med_b - med_a) * 1000
    sd = statistics.pstdev(samples_a + samples_b) or 1e-9
    t = abs(med_a - med_b) / sd
    return abs(delta_ms) >= min_delta_ms and t >= 3.0, delta_ms, t
