"""Shared existence-verification primitives for recon/passive probes.

Akar sebagian besar false positive pada scanner "cek keberadaan file/endpoint":
modul mem-fetch sebuah path, melihat HTTP 200, lalu menyatakan "terekspos" —
tanpa menyadari banyak situs (terutama SPA / framework dengan catch-all route)
mengembalikan `index.html` berstatus 200 untuk PATH APA PUN, termasuk `/.env`,
`/api/`, `/admin/`, dst. Karena HTML itu penuh karakter seperti `=` dan `{`,
marker lemah ikut lolos.

Modul ini menyediakan:
  - `NegativeBaseline`: contoh respons untuk path yang PASTI tidak ada, sebagai
    pembanding. `looks_like_catchall(resp)` True bila respnya menyerupai pola
    "halaman yang sama untuk segala path" (soft-404 / SPA fallback) atau homepage.
  - Validator konten spesifik tipe: `is_dotenv`, `is_json_doc`, `is_xml_doc`,
    `looks_like_html`, `is_binaryish`, `body_has`.
  - `verify_real`: gabungan — sebuah path baru dianggap resource nyata HANYA bila
    statusnya OK, BUKAN catch-all, dan (opsional) lolos validator konten.
"""
from __future__ import annotations

import difflib
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable

_CAP = 6000  # banding hanya potongan awal body agar cepat


def _norm(text: str) -> str:
    text = text[:_CAP]
    text = re.sub(r"[0-9a-fA-F]{16,}", "", text)
    text = re.sub(r"\b\d{6,}\b", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def similarity(a: str | None, b: str | None) -> float:
    if not a and not b:
        return 1.0
    if a is None or b is None:
        return 0.0
    na, nb = _norm(a), _norm(b)
    if not na and not nb:
        return 1.0
    return difflib.SequenceMatcher(None, na, nb).ratio()


@dataclass
class _Resp:
    status: int
    ctype: str
    body: str


@dataclass
class NegativeBaseline:
    statuses: set[int] = field(default_factory=set)
    samples: list[_Resp] = field(default_factory=list)
    home: _Resp | None = None

    def looks_like_catchall(self, status: int, body: str, ctype: str = "") -> bool:
        """True bila respons ini sepertinya bukan resource unik, melainkan halaman
        fallback yang sama yang dikembalikan untuk path tak-ada / homepage."""
        # Path acak yang pasti tak ada mengembalikan status yang sama → server tak
        # membedakan ada/tidak (catch-all). 200 untuk path-ngawur = sinyal terkuat.
        if status in self.statuses:
            for s in self.samples:
                if similarity(body, s.body) >= 0.88:
                    return True
        # Respons identik dengan homepage → kemungkinan SPA fallback.
        if self.home and self.home.status == status and similarity(body, self.home.body) >= 0.92:
            return True
        return False


def negative_baseline(client: Any, target: Any) -> NegativeBaseline:
    """Sampel 2 path acak (pasti 404) + homepage. Hasil di-cache per origin."""
    origin = target.origin
    cache = _BASELINE_CACHE
    if origin in cache:
        return cache[origin]

    nb = NegativeBaseline()
    rnd = secrets.token_hex(8)
    probes = [f"{origin}/{rnd}-cyberloka-404", f"{origin}/{rnd}/{rnd}.html"]
    for u in probes:
        r = client.get(u, allow_redirects=False)
        if r is None:
            continue
        body = (r.text or "")[:_CAP]
        nb.statuses.add(r.status_code)
        nb.samples.append(_Resp(r.status_code, r.headers.get("Content-Type", ""), body))
    home = client.get(origin + "/", allow_redirects=False)
    if home is not None:
        nb.home = _Resp(home.status_code, home.headers.get("Content-Type", ""), (home.text or "")[:_CAP])

    cache[origin] = nb
    return nb


_BASELINE_CACHE: dict[str, NegativeBaseline] = {}


def reset_cache() -> None:
    _BASELINE_CACHE.clear()


# --------------------------- content validators ---------------------------

def looks_like_html(body: str) -> bool:
    head = body[:400].lower()
    return "<!doctype html" in head or "<html" in head or "<head" in head or "<body" in head


def is_dotenv(body: str) -> bool:
    """Body terlihat seperti file .env asli: bukan HTML, dan punya >=2 baris
    KEY=VALUE bergaya environment variable."""
    if not body or looks_like_html(body):
        return False
    lines = [ln for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    kv = [ln for ln in lines if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", ln)]
    return len(kv) >= 2 and len(kv) >= len(lines) * 0.5


def is_json_doc(ctype: str, body: str) -> bool:
    if "json" in (ctype or "").lower():
        try:
            json.loads(body)
            return True
        except Exception:
            return body.strip()[:1] in "{["
    s = body.strip()
    if s[:1] in "{[":
        try:
            json.loads(s)
            return True
        except Exception:
            return False
    return False


def is_xml_doc(ctype: str, body: str) -> bool:
    if "xml" in (ctype or "").lower():
        return True
    return body.strip().startswith("<?xml") or body.strip().startswith("<")


def is_binaryish(ctype: str) -> bool:
    c = (ctype or "").lower()
    return any(t in c for t in ("octet-stream", "application/x-", "force-download")) and "html" not in c


def body_has(body: str, marker: str) -> bool:
    return bool(marker) and marker.lower() in (body or "").lower()


# --------------------------- high-level helper ---------------------------

def verify_real(
    client: Any,
    target: Any,
    url: str,
    *,
    validator: Callable[[str, str], bool] | None = None,
    allow_redirects: bool = False,
):
    """Fetch `url` dan kembalikan response HANYA bila resource nyata & terverifikasi.

    Mengembalikan None bila: gagal, status >= 400, terlihat catch-all/soft-404, atau
    `validator(ctype, body)` mengembalikan False. `validator` menerima (content_type, body).
    """
    r = client.get(url, allow_redirects=allow_redirects)
    if r is None or r.status_code >= 400:
        return None
    body = r.text or ""
    ctype = r.headers.get("Content-Type", "")
    nb = negative_baseline(client, target)
    if nb.looks_like_catchall(r.status_code, body, ctype):
        return None
    if validator is not None and not validator(ctype, body):
        return None
    return r
