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

Bahasa Indonesia karena report end-user adalah engineer Indonesia.
"""
from __future__ import annotations

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

    Berguna untuk source_leak / sensitive_files: kalau /backup.sql balas
    HTML SPA, JANGAN dilaporkan sebagai "SQL dump bocor".
    """
    if not body:
        return False
    low = body.lower()
    if "<html" in low and ("<div id=\"__next\"" in low or "<div id=\"root\"" in low
                            or "<noscript>" in low):
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
