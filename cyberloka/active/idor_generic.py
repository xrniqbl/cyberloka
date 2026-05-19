"""Generic IDOR probe — strict-validation v0.10.1.

False-positive guards:
  * Stable baseline: kalau response panjangnya berubah-ubah antar fetch
    (mis. timestamp di body), TIDAK bisa dipakai untuk deteksi IDOR.
  * Mutated ID harus konsisten beda DUA fetch berturut.
  * Skip kalau mutated body sebenarnya adalah halaman 'forbidden' / 'not
    found' yang masih balas 200 (soft-403).
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
    stable_baseline,
)
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state
from cyberloka.reporting.awam import get_awam

ID_PATH_HINTS = ("user", "account", "profile", "order", "invoice", "ticket",
                 "transaction", "payment", "reservation", "booking",
                 "message", "doc", "file", "report")

SOFT_FORBID_HINTS = (
    "forbidden", "unauthorized", "permission denied", "tidak diizinkan",
    "akses ditolak", "not found", "tidak ditemukan", "404",
)


def _candidates(target: Target, config: ScanConfig) -> list[tuple[str, str, int]]:
    state = get_state(config)
    pool = []
    if state:
        pool = state.urls + state.param_urls
    pool = list(dict.fromkeys(pool + [target.base_url]))
    out: list[tuple[str, str, int]] = []
    for u in pool:
        parsed = urlparse(u)
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            if v.isdigit() and int(v) > 0 and k.lower() in ("id", "uid", "userid",
                                                             "order_id", "invoice_id",
                                                             "ref", "ticket_id"):
                out.append((u, f"query:{k}", int(v)))
                break
        segs = [s for s in parsed.path.split("/") if s]
        for i, seg in enumerate(segs):
            if seg.isdigit() and i > 0 and any(h in segs[i - 1].lower() for h in ID_PATH_HINTS):
                out.append((u, f"path:{i}", int(seg)))
                break
    return out[:15]


def _mutate_path(url: str, idx: int, new_id: int) -> str:
    parsed = urlparse(url)
    segs = parsed.path.split("/")
    counted = 0
    for j, s in enumerate(segs):
        if s == "":
            continue
        if counted == idx:
            segs[j] = str(new_id)
            break
        counted += 1
    return urlunparse(parsed._replace(path="/".join(segs)))


def _mutate_query(url: str, key: str, new_value: str) -> str:
    parsed = urlparse(url)
    new = [(k, new_value if k == key else v)
           for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunparse(parsed._replace(query=urlencode(new)))


def _looks_forbidden(body: str) -> bool:
    low = (body or "").lower()
    return any(h in low for h in SOFT_FORBID_HINTS)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary, awam_steps = get_awam("idor_generic")
    candidates = _candidates(target, config)
    if not candidates:
        return findings
    try:
        for url, where, n in candidates:
            stable, lo, hi = stable_baseline(client, url)
            if not stable:
                continue
            base_len = (lo + hi) // 2

            for delta in (-1, +1, +5):
                new_id = max(1, n + delta)
                if new_id == n:
                    continue
                if where.startswith("query:"):
                    mutated = _mutate_query(url, where.split(":", 1)[1], str(new_id))
                else:
                    mutated = _mutate_path(url, int(where.split(":", 1)[1]), new_id)

                # Two-shot for stability
                r1 = client.get(mutated)
                if r1 is None or r1.status_code != 200:
                    continue
                body1 = r1.text or ""
                if _looks_forbidden(body1):
                    continue
                if abs(len(body1) - base_len) == 0:
                    continue
                if abs(len(body1) - base_len) >= base_len * 0.5:
                    continue
                # Confirm fetch
                r2 = client.get(mutated)
                if r2 is None or r2.status_code != 200:
                    continue
                body2 = r2.text or ""
                # Mutated response should be CONSISTENT to itself across 2 fetch.
                if abs(len(body1) - len(body2)) > 200:
                    continue
                # Direction same vs baseline.
                if (len(body1) > base_len) != (len(body2) > base_len):
                    continue

                proof = ValidationProof(
                    method="stable-baseline+double-fetch",
                    confirmed=True,
                    steps=[
                        f"Baseline pada `{url}` stabil: {lo}..{hi} bytes (>=2 fetch).",
                        f"Mutate `{where}` {n} → {new_id}.",
                        f"Mutated fetch #1 = {len(body1)} bytes (selisih {abs(len(body1)-base_len)}).",
                        f"Mutated fetch #2 = {len(body2)} bytes (delta {abs(len(body1)-len(body2))} antar fetch).",
                        "Body bukan halaman 'forbidden/not found'.",
                    ],
                    samples=[
                        f"baseline_avg={base_len}",
                        f"mutated_len_1={len(body1)} mutated_len_2={len(body2)}",
                    ],
                )
                findings.append(Finding(
                    module="idor_generic",
                    title=f"Kemungkinan IDOR pada `{where}` (id {n} → {new_id})",
                    severity=Severity.HIGH,
                    description=("Mengubah ID resource menghasilkan response 200 dengan "
                                 "konten berbeda dan stabil di antara dua fetch — sangat "
                                 "mungkin objek dapat diakses tanpa otorisasi per-user."),
                    target=mutated,
                    evidence=(f"baseline={base_len}, mutated_len_1={len(body1)}, "
                              f"mutated_len_2={len(body2)}, status=200"),
                    cwe="CWE-639",
                    confidence="firm",
                    urls=[mutated],
                    remediation=("Validasi authorization di layer query: "
                                 "`WHERE id=? AND owner_id=?`. Gunakan UUID/HMAC bila perlu."),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
                    ],
                    extra=build_extra(
                        proof=proof,
                        awam_steps=awam_steps,
                        awam_summary=awam_summary,
                    ),
                ))
                break
    finally:
        client.close()
    return findings
