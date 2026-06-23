"""Helpers shared by active checks.

Selain util mutasi parameter (``iter_param_urls``/``append_param``), modul ini
menyediakan **smart targeting engine** (:func:`candidate_urls`,
:func:`candidate_forms`) yang memperluas jangkauan scanner injeksi.

Latar belakang (v0.10.7):
    Dulu scanner inti (sqli/xss/lfi/cmdi/ssti/redirect/csti) HANYA menguji
    ``target.base_url`` dengan satu parameter sintetis (mis. ``?id=1``).
    Akibatnya, di website nyata yang punya banyak endpoint berparameter
    (``/cari?q=``, ``/produk?id=``, ``/profil?user=``) scanner praktis tidak
    pernah menyentuh permukaan serang yang sebenarnya — logika validasinya
    kuat, tapi cakupannya nyaris nol.

    :func:`candidate_urls` menggabungkan ``base_url`` dengan SEMUA
    ``param_urls`` yang ditemukan crawler, melakukan dedup berbasis "bentuk"
    (path + nama-nama parameter) supaya endpoint serupa (``/produk?id=1`` vs
    ``/produk?id=2``) tidak diuji berulang, lalu membatasi jumlahnya agar scan
    tetap cepat. Hasilnya: cakupan deteksi naik drastis TANPA menurunkan
    kualitas validasi per-titik (false-positive guard tiap scanner tetap utuh).
"""
from __future__ import annotations

from typing import Iterator
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def has_query(url: str) -> bool:
    return bool(urlparse(url).query)


def iter_param_urls(url: str, payload: str):
    """Yield (param, mutated_url) for each query parameter, replacing its value with payload."""
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return
    for i, (k, _) in enumerate(params):
        new = list(params)
        new[i] = (k, payload)
        new_q = urlencode(new, doseq=True)
        yield k, urlunparse(parsed._replace(query=new_q))


def append_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    params.append((key, value))
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


# ---------------------------------------------------------------------------
# Smart targeting engine
# ---------------------------------------------------------------------------


def _shape_key(url: str) -> tuple:
    """Kunci dedup berbasis bentuk URL (scheme, host, path, set nama param).

    Endpoint dengan path & nama parameter sama dianggap "bentuk" yang sama
    walau nilai parameternya berbeda — cukup diuji satu kali.
    """
    p = urlparse(url)
    names = tuple(sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True)))
    return (p.scheme, p.netloc.lower(), p.path, names)


def _get_crawl_state(config):
    """Ambil CrawlState hasil crawler (None bila crawler belum jalan)."""
    try:
        from cyberloka.recon.crawler import get_state
    except Exception:
        return None
    try:
        return get_state(config)
    except Exception:
        return None


def candidate_urls(
    target,
    config,
    *,
    fallback_param: str | None = None,
    fallback_value: str = "1",
    include_base: bool = True,
    limit: int = 40,
) -> list[str]:
    """Daftar URL berparameter yang layak difuzz untuk injeksi query-param.

    Menggabungkan ``target.base_url`` dengan ``param_urls`` hasil crawler.

    Args:
        fallback_param: bila sebuah URL belum punya query string DAN argumen
            ini di-set, parameter sintetis ``fallback_param=fallback_value``
            ditambahkan agar scanner punya titik suntik. Scanner yang hanya
            relevan pada parameter nyata (mis. open-redirect) memakai ``None``
            sehingga URL tanpa query di-skip.
        include_base: apakah ``base_url`` ikut diuji (default True).
        limit: batas jumlah URL agar scan tetap cepat (dedup by bentuk dulu).

    Returns:
        List URL unik (berdasarkan bentuk) yang punya query string.
    """
    urls: list[str] = []
    seen: set[tuple] = set()

    def _add(u: str | None) -> None:
        if not u or len(urls) >= limit:
            return
        if "?" not in u and fallback_param:
            u = append_param(u, fallback_param, fallback_value)
        if "?" not in u:
            return  # tidak ada yang bisa difuzz
        key = _shape_key(u)
        if key in seen:
            return
        seen.add(key)
        urls.append(u)

    if include_base:
        _add(target.base_url)

    state = _get_crawl_state(config)
    if state is not None:
        # param_urls (punya query) diprioritaskan; lalu URL biasa dengan fallback.
        for u in getattr(state, "param_urls", []) or []:
            _add(u)
        if fallback_param:
            for u in getattr(state, "urls", []) or []:
                _add(u)

    return urls[:limit]


def candidate_forms(
    config,
    *,
    require_password: bool | None = None,
    limit: int = 20,
) -> list[dict]:
    """Daftar form hasil crawler (dedup by method+action+nama input).

    Args:
        require_password: True -> hanya form yang punya field password (login);
            False -> hanya form tanpa password; None -> semua form.
        limit: batas jumlah form.
    """
    state = _get_crawl_state(config)
    if state is None:
        return []
    out: list[dict] = []
    seen: set[tuple] = set()
    for f in getattr(state, "forms", []) or []:
        inputs = f.get("inputs") or []
        names = tuple(i.get("name") for i in inputs)
        key = (f.get("method"), f.get("action"), names)
        if key in seen:
            continue
        has_pw = any((i.get("type") or "").lower() == "password" for i in inputs)
        if require_password is True and not has_pw:
            continue
        if require_password is False and has_pw:
            continue
        seen.add(key)
        out.append(f)
        if len(out) >= limit:
            break
    return out


def form_fuzz_fields(form: dict) -> list[str]:
    """Nama field yang layak disuntik (kecuali submit/button/hidden/csrf)."""
    skip_types = {"submit", "button", "image", "reset", "file"}
    fields: list[str] = []
    for i in form.get("inputs") or []:
        name = i.get("name")
        if not name:
            continue
        itype = (i.get("type") or "").lower()
        if itype in skip_types:
            continue
        fields.append(name)
    return fields


def build_form_data(form: dict, inject_field: str, payload: str) -> dict:
    """Bangun body form: ``inject_field`` diisi payload, sisanya nilai benign.

    Field hidden/submit memakai nilai default-nya (atau ``x``) agar request
    tidak ditolak karena field wajib kosong.
    """
    data: dict[str, str] = {}
    for i in form.get("inputs") or []:
        name = i.get("name")
        if not name:
            continue
        itype = (i.get("type") or "").lower()
        if name == inject_field:
            data[name] = payload
        elif itype in ("submit", "button", "hidden", "image"):
            data[name] = i.get("value") or "x"
        else:
            data[name] = i.get("value") or "cyberloka"
    return data


def submit_form(client, form: dict, data: dict):
    """Kirim form sesuai method-nya. Return response atau None."""
    if not data:
        return None
    action = form.get("action")
    if not action:
        return None
    if (form.get("method") or "get").lower() == "post":
        return client.post(action, data=data)
    return client.get(action, params=data)
