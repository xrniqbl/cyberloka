"""Generic IDOR probe on URLs containing numeric IDs."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

ID_PATH_HINTS = ("user", "account", "profile", "order", "invoice", "ticket",
                 "transaction", "payment", "reservation", "booking",
                 "message", "doc", "file", "report")


def _candidates(target: Target, config: ScanConfig) -> list[tuple[str, str, int]]:
    """Return (url, where, current_id) tuples. where = 'query:foo' or 'path'."""
    state = get_state(config)
    pool = []
    if state:
        pool = state.urls + state.param_urls
    pool = list(dict.fromkeys(pool + [target.base_url]))
    out: list[tuple[str, str, int]] = []
    for u in pool:
        parsed = urlparse(u)
        # Query param numeric
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            if v.isdigit() and int(v) > 0 and k.lower() in ("id", "uid", "userid",
                                                             "order_id", "invoice_id",
                                                             "ref", "ticket_id"):
                out.append((u, f"query:{k}", int(v)))
                break
        # Numeric segment in path setelah hint kata
        segs = [s for s in parsed.path.split("/") if s]
        for i, seg in enumerate(segs):
            if seg.isdigit() and i > 0 and any(h in segs[i - 1].lower() for h in ID_PATH_HINTS):
                out.append((u, f"path:{i}", int(seg)))
                break
    return out[:15]


def _mutate_path(url: str, idx: int, new_id: int) -> str:
    parsed = urlparse(url)
    segs = parsed.path.split("/")
    # idx counted in non-empty list; map back to actual index in split list
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


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    candidates = _candidates(target, config)
    if not candidates:
        return findings
    try:
        for url, where, n in candidates:
            r0 = client.get(url)
            if r0 is None or r0.status_code >= 400:
                continue
            base_body = r0.text or ""
            base_len = len(base_body)
            for delta in (-1, +1, +5):
                new_id = max(1, n + delta)
                if new_id == n:
                    continue
                if where.startswith("query:"):
                    mutated = _mutate_query(url, where.split(":", 1)[1], str(new_id))
                else:
                    mutated = _mutate_path(url, int(where.split(":", 1)[1]), new_id)
                r = client.get(mutated)
                if r is None or r.status_code != 200:
                    continue
                body = r.text or ""
                # 200 OK + body berbeda secara signifikan (>5%) tapi struktur mirip
                if abs(len(body) - base_len) > 0 and abs(len(body) - base_len) < base_len * 0.5:
                    findings.append(Finding(
                        module="idor_generic",
                        title=f"Kemungkinan IDOR pada `{where}` (id {n} → {new_id})",
                        severity=Severity.HIGH,
                        description=("Mengubah ID resource menghasilkan response 200 dengan "
                                     "konten berbeda. Verifikasi apakah otorisasi per-user "
                                     "diterapkan, atau objek bisa diakses oleh siapa pun."),
                        target=mutated,
                        evidence=f"original_len={base_len}, mutated_len={len(body)}, status=200",
                        cwe="CWE-639", confidence="tentative",
                        remediation=("Validasi authorization di layer query: "
                                     "`WHERE id=? AND owner_id=?`. Gunakan UUID/HMAC bila perlu."),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
                        ],
                    ))
                    break
    finally:
        client.close()
    return findings
