"""IDOR (Insecure Direct Object Reference) heuristic detector.

PERINGATAN: deteksi IDOR yang asli butuh DUA akun berbeda + pengetahuan
business logic. Modul ini HANYA memberikan indikator awal:

1. Endpoint yang URL-nya memuat numeric/UUID id (mis. /user/123, /invoice/abc-uuid).
2. Endpoint berparameter id yang merespons 200 OK pada nilai berurutan
   (mis. id=1, id=2, id=3 semua return 200 dengan body berbeda).
3. Endpoint yang return JSON object dengan field 'id'/'userId'/'email'/'phone'
   (kandidat data leakage tanpa otorisasi).

Tidak melakukan privilege escalation atau aksi destruktif. Ini *hint*
untuk tester manual.
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

NUMERIC_PATH_RE = re.compile(r"/(\d{1,8})(?=/|$|\?)")
UUID_PATH_RE = re.compile(
    r"/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?=/|$|\?)",
    re.I,
)
ID_PARAM_HINTS = ("id", "userid", "user_id", "uid", "accountid", "account_id",
                  "orderid", "order_id", "invoiceid", "invoice_id", "transid",
                  "trans_id", "ticketid", "no", "nomor")
SENSITIVE_FIELD_HINTS = ("email", "phone", "telepon", "nik", "ktp", "address",
                         "alamat", "saldo", "balance", "userid", "user_id")


def _candidate_endpoints(target: Target) -> list[str]:
    out: list[str] = []
    discovered = getattr(target, "discovered", None)
    if discovered is None:
        return out
    for ep in getattr(discovered, "endpoints", []):
        if ep.method.upper() != "GET":
            continue
        url = ep.url
        if NUMERIC_PATH_RE.search(url) or UUID_PATH_RE.search(url):
            out.append(url)
            continue
        # query string punya param id
        for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
            if any(h in k.lower() for h in ID_PARAM_HINTS):
                out.append(url)
                break
    # dedup
    return list(dict.fromkeys(out))[:15]


def _walk_increment(url: str) -> tuple[str, str] | None:
    """Hasilkan dua URL: id N dan N+1, atau None bila tidak ada id numerik."""
    p = urlparse(url)

    # Path-based
    m = NUMERIC_PATH_RE.search(p.path)
    if m:
        cur = int(m.group(1))
        nxt = cur + 1
        new_path = p.path.replace(f"/{cur}", f"/{nxt}", 1)
        a = url
        b = urlunparse(p._replace(path=new_path))
        return a, b

    # Query-based
    pairs = parse_qsl(p.query, keep_blank_values=True)
    for i, (k, v) in enumerate(pairs):
        if any(h in k.lower() for h in ID_PARAM_HINTS) and v.isdigit():
            cur = int(v)
            nxt = cur + 1
            new_pairs = list(pairs)
            new_pairs[i] = (k, str(nxt))
            return url, urlunparse(p._replace(query=urlencode(new_pairs, doseq=True)))
    return None


def _scan_json_for_sensitive(body: str) -> list[str]:
    try:
        d = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return []
    sensitive: list[str] = []

    def walk(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_low = k.lower()
                if any(h in key_low for h in SENSITIVE_FIELD_HINTS):
                    sensitive.append(f"{prefix}{k}")
                walk(v, prefix + k + ".")
        elif isinstance(obj, list) and obj:
            walk(obj[0], prefix + "[0].")
    walk(d)
    return list(dict.fromkeys(sensitive))[:10]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    candidates = _candidate_endpoints(target)
    if not candidates:
        return findings

    client = HttpClient(config)
    try:
        for url in candidates:
            walk = _walk_increment(url)
            if not walk:
                continue
            a, b = walk
            r1 = client.get(a)
            r2 = client.get(b)
            if r1 is None or r2 is None:
                continue
            if r1.status_code != 200 or r2.status_code != 200:
                continue
            body1 = r1.text or ""
            body2 = r2.text or ""
            if not body1 or not body2:
                continue
            if abs(len(body1) - len(body2)) < 10:
                continue  # response identik -> kemungkinan rendah

            # cek apakah konten cukup berbeda (>10% delta) -> indikator id berbeda diserve
            ratio = abs(len(body1) - len(body2)) / max(len(body1), len(body2))
            ctype = r2.headers.get("Content-Type", "")
            sensitive_fields: list[str] = []
            if "json" in ctype.lower():
                sensitive_fields = _scan_json_for_sensitive(body2)

            if ratio < 0.05 and not sensitive_fields:
                continue

            sev = Severity.HIGH if sensitive_fields else Severity.MEDIUM
            findings.append(
                Finding(
                    module="idor",
                    title=f"Indikasi IDOR pada endpoint id-numerik: {a}",
                    severity=sev,
                    confidence="tentative",
                    description=(
                        "Mengubah id numerik di URL mengembalikan response 200 yang "
                        "berbeda. Bila endpoint ini hanya boleh diakses pemilik object, "
                        "ini IDOR. Verifikasi manual: login sebagai user A, akses "
                        "object milik user B."
                    ),
                    target=a,
                    evidence=(
                        f"original: {a} (len={len(body1)})\n"
                        f"incremented: {b} (len={len(body2)})\n"
                        f"sensitive_fields_di_response: {sensitive_fields or '-'}"
                    ),
                    cwe="CWE-639",
                    remediation=(
                        "Tambahkan otorisasi tingkat-objek: setiap GET/PATCH/DELETE "
                        "harus cek apakah current_user adalah pemilik object atau "
                        "punya role yang berhak. JANGAN andalkan obscurity dari id "
                        "numerik. Pertimbangkan ganti dengan UUID + ACL."
                    ),
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                    ],
                )
            )
    finally:
        client.close()
    return findings
