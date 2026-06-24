"""Finding validation gate.

Tujuan: pastikan hanya finding yang **benar-benar** valid yang masuk report.

Tahapan:
    1. **De-duplicate** — finding yang title+target identik digabung.
    2. **Sanity check** — buang finding tanpa target / bukti / title.
    3. **Re-probe (opsional)** — untuk severity HIGH/CRITICAL dengan target URL,
       lakukan satu request ringan untuk konfirmasi target masih reachable
       dan, bila modul men-set `extra["reverify"]`, cocokkan marker.
    4. **Confidence floor** — finding `tentative` yang tidak punya evidence
       cukup di-drop atau di-downgrade.

Modul ini dipanggil scanner.py *setelah* semua modul selesai dan *sebelum*
report dibangun.
"""
from __future__ import annotations

import re
from dataclasses import replace
from typing import Iterable

from cyberloka.core.config import ScanConfig
from cyberloka.core.finding import Finding, Severity
from cyberloka.core.http_client import HttpClient
from cyberloka.core.logger import get_logger

# Severity yang wajib di-re-probe sebelum dilaporkan.
_REPROBE_SEVERITY = {Severity.CRITICAL, Severity.HIGH}

# Modul yang TIDAK perlu re-probe (DNS-only / metadata / scoring).
_SKIP_REPROBE_MODULES = {
    "dns", "whois", "ports", "subdomains", "subdomain_takeover",
    "email_security", "email_security_extended", "favicon_hash",
    "tls", "exif_leak", "homoglyph_check", "outdated_libs",
    "burst", "rate_limit", "crawler",
}

# Marker untuk request retry: berapa kali coba ulang sebelum drop.
_REPROBE_RETRIES = 1


def _is_url(s: str | None) -> bool:
    return bool(s) and s.startswith(("http://", "https://"))


def _evidence_strong(f: Finding) -> bool:
    """True jika evidence finding cukup spesifik untuk dipercaya."""
    ev = (f.evidence or "").strip()
    if not ev:
        return False
    # Heuristik: evidence lebih dari sekadar status/length saja sudah cukup.
    if len(ev) < 12:
        return False
    # Angka HTTP saja tanpa konten lain → lemah.
    if re.fullmatch(r"(?:HTTP\s*\d{3}|status[=:]?\s*\d{3}|len[=:]?\s*\d+)", ev):
        return False
    return True


def _dedupe_key(f: Finding) -> tuple[str, str, str]:
    # Module + title + target → kunci unik.
    return (f.module, f.title.lower().strip(), (f.target or "").rstrip("/"))


def _reverify(client: HttpClient, f: Finding) -> bool:
    """Coba ulang request ke f.target. Return True jika finding masih valid."""
    if not _is_url(f.target):
        return True  # tidak bisa di-reprobe → trust modul
    if f.module in _SKIP_REPROBE_MODULES:
        return True
    # Modul men-set extra["reverify"] = {"marker": "...", "in_body": True}
    rule = f.extra.get("reverify") if isinstance(f.extra, dict) else None
    method = (rule or {}).get("method", "GET").upper()
    expected_marker = (rule or {}).get("marker")
    expected_status = (rule or {}).get("status")  # int atau iterable
    in_body = (rule or {}).get("in_body", True)

    for _ in range(_REPROBE_RETRIES + 1):
        r = client.request(method, f.target, allow_redirects=True)
        if r is None:
            continue
        if expected_status is not None:
            try:
                ok_status = (r.status_code in expected_status
                             if not isinstance(expected_status, int)
                             else r.status_code == expected_status)
            except TypeError:
                ok_status = False
            if not ok_status:
                continue
        if expected_marker:
            haystack = (r.text or "") if in_body else " ".join(
                f"{k}: {v}" for k, v in r.headers.items()
            )
            if expected_marker.lower() not in haystack.lower():
                continue
        return True
    return False


def validate(
    findings: Iterable[Finding],
    config: ScanConfig,
    *,
    reprobe: bool = True,
) -> list[Finding]:
    """Filter & verifikasi finding sebelum report.

    Args:
        findings: hasil mentah semua scanner.
        config: ScanConfig (untuk membuat HttpClient verifikasi).
        reprobe: kalau False, lewati network re-probe (mode offline / unit test).

    Returns:
        list[Finding] yang sudah dibersihkan, di-dedupe, dan diverifikasi.
    """
    log = get_logger()
    raw = [f for f in findings if f and f.title and f.target]
    if not raw:
        return []

    # 1. de-dupe
    by_key: dict[tuple[str, str, str], Finding] = {}
    for f in raw:
        k = _dedupe_key(f)
        prev = by_key.get(k)
        if not prev:
            by_key[k] = f
            continue
        # Pilih yang severity lebih tinggi atau confidence lebih tinggi.
        if f.severity.order < prev.severity.order:
            by_key[k] = f
        elif f.confidence == "confirmed" and prev.confidence != "confirmed":
            by_key[k] = f
    deduped = list(by_key.values())
    log.info("[validator] dedupe %d -> %d", len(raw), len(deduped))

    # 2. sanity drop
    cleaned: list[Finding] = []
    for f in deduped:
        # tentative + evidence lemah + bukan severity rendah → drop.
        if f.confidence == "tentative" and not _evidence_strong(f) \
                and f.severity in (Severity.CRITICAL, Severity.HIGH):
            log.info("[validator] drop tentative tanpa evidence kuat: %s", f.title)
            continue
        cleaned.append(f)

    # 3. re-probe HIGH/CRITICAL
    if not reprobe or not cleaned:
        return cleaned

    needs_reprobe = [f for f in cleaned
                     if f.severity in _REPROBE_SEVERITY
                     and f.module not in _SKIP_REPROBE_MODULES
                     and _is_url(f.target)]
    if not needs_reprobe:
        return cleaned

    client = HttpClient(config)
    valid: list[Finding] = []
    invalid_keys: set[tuple[str, str, str]] = set()
    try:
        for f in needs_reprobe:
            ok = _reverify(client, f)
            if ok:
                # naikkan confidence kalau sebelumnya tentative.
                if f.confidence == "tentative":
                    new = replace(f, confidence="firm")
                    cleaned[cleaned.index(f)] = new
            else:
                log.info("[validator] gagal reverifikasi -> drop: %s", f.title)
                invalid_keys.add(_dedupe_key(f))
    finally:
        client.close()

    for f in cleaned:
        if _dedupe_key(f) in invalid_keys:
            continue
        valid.append(f)

    log.info("[validator] final %d finding (drop %d tidak tervalidasi)",
             len(valid), len(cleaned) - len(valid))
    return valid
