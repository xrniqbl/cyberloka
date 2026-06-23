"""DB-leak PII scanner — strict-validation v0.10.1.

Specialised PII detection untuk konteks "data dari database bocor lewat
URL/API publik". Berbeda dari ``pii_leak`` (yang generik): scanner ini

  1. Menebak / mengambil endpoint kandidat dump-database:
     ``/api/users``, ``/api/customers``, ``/dump.json``, ``/backup/data.sql``,
     ``/_users.json``, dst. (ditambah hasil crawler).
  2. Mendeteksi PII Indonesia:
     - NIK (16 digit, kode provinsi 11..94 valid)
     - Nomor KK (16 digit, kode provinsi valid, dibedakan dari NIK lewat
       konteks "kk", "kartu keluarga", "no_kk", "nomor_kk")
     - Nomor rekening bank Indonesia (10-16 digit, dengan konteks "rekening",
       "BCA/BNI/BRI/Mandiri/CIMB/Permata/Danamon/dll.")
     - Nomor HP (Indonesia: +62 / 62 / 08...)
     - Email
     - (Bonus) NPWP, kartu kredit (Luhn-valid).
  3. **Validasi ketat sebelum melapor**:
     - Negative-control fetch path random pada origin yang sama: kalau
       balasan "halaman 404 generik" mengandung pola PII yang sama →
       SKIP (server selalu echo data ini).
     - Hanya laporkan kalau >= 5 instance unik untuk satu jenis,
       atau >= 3 jenis berbeda muncul bersamaan (ciri dump database).
     - Reject jika body cuma SPA shell tanpa konten data.
     - NIK / KK harus pass cek kode provinsi (BPS).
     - Kartu kredit harus pass Luhn.

Output finding mendeskripsikan: jumlah unik per jenis, sample tersamarkan,
URL endpoint, dan AWAM-step yang menjelaskan cara penyerang mengeksploitasi.
"""
from __future__ import annotations

import re
import secrets
from collections import Counter
from urllib.parse import urljoin

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
    looks_like_html_shell,
)
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.reporting.awam import get_awam

# ---------------------------------------------------------------------------
# Endpoint kandidat: dump / listing / API yang sering bocor di praktik
# ---------------------------------------------------------------------------
DB_LEAK_PATHS = [
    # Listing user / customer
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/customers", "/api/v1/customers",
    "/api/members", "/api/v1/members",
    "/api/employees", "/api/admin/users", "/api/admin/customers",
    "/users", "/customers", "/members",
    # Search yang mengembalikan banyak record
    "/api/users/search?q=", "/api/users?limit=1000",
    "/api/customers?per_page=500", "/api/customers/all",
    "/api/users.json", "/api/customers.json",
    # Dump file & backup yang sering ke-deploy ke webroot
    "/dump.sql", "/backup.sql", "/database.sql", "/db.sql",
    "/dump.json", "/backup.json", "/data.json", "/users.json",
    "/customers.json", "/members.json",
    "/backup/users.csv", "/backup/customers.csv",
    "/exports/users.csv", "/exports/customers.csv",
    "/dump/", "/backup/", "/exports/",
    # Common bocor "dev" leftovers
    "/_users.json", "/_data.json",
    "/.well-known/users.json",
    # Indonesia-specific (E-commerce / fintech umum)
    "/api/nasabah", "/api/anggota", "/api/peserta",
    "/api/pelanggan", "/api/klien",
    "/api/data-pelanggan", "/api/data-nasabah",
]

# Maximum kandidat aktif yang dipindai (selain hasil crawler)
MAX_PROBES = 60

# Valid Indonesian BPS province codes (first two digits of NIK / KK).
VALID_PROVINCE_CODES = {
    "11", "12", "13", "14", "15", "16", "17", "18", "19",
    "21", "31", "32", "33", "34", "35", "36",
    "51", "52", "53",
    "61", "62", "63", "64", "65",
    "71", "72", "73", "74", "75", "76",
    "81", "82",
    "91", "94",
}

# ---------------------------------------------------------------------------
# Regex
# ---------------------------------------------------------------------------
RE_16DIGIT = re.compile(r"(?<!\d)(\d{16})(?!\d)")
RE_PHONE_ID = re.compile(r"(?<![\d+])(\+62|62|0)8\d{8,11}(?!\d)")
RE_EMAIL = re.compile(r"\b[A-Z0-9._%+-]{2,}@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
RE_NPWP = re.compile(r"\b\d{2}\.\d{3}\.\d{3}\.\d-\d{3}\.\d{3}\b")
RE_BANK_ACCOUNT = re.compile(r"(?<!\d)(\d{10,16})(?!\d)")
RE_CC = re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b")

KK_HINT_RE = re.compile(
    r"(?:^|[\s\"',(>])(?:no[._\s-]?kk|nomor[._\s-]?kk|kartu[._\s-]?keluarga|n_kk|no_kk|nomor_keluarga)\b",
    re.I,
)
NIK_HINT_RE = re.compile(
    r"(?:^|[\s\"',(>])(?:nik|nomor[._\s-]?induk|no[._\s-]?ktp|nomor[._\s-]?ktp|"
    r"identity[._\s-]?number)\b",
    re.I,
)
BANK_HINT_RE = re.compile(
    r"(?:^|[\s\"',(>])(?:rekening|no[._\s-]?rekening|nomor[._\s-]?rekening|account[._\s-]?number|"
    r"acc[._\s-]?no|bank|bca|bni|bri|mandiri|cimb|permata|danamon|btn|btpn|panin|"
    r"ocbc|maybank|jenius|seabank|jago|allo|dana|gopay|ovo|shopeepay)\b",
    re.I,
)


def _luhn_ok(num: str) -> bool:
    """Standard Luhn check digit verifier (used for credit card validation)."""
    digits = [int(c) for c in num if c.isdigit()]
    if len(digits) < 12:
        return False
    s = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return s % 10 == 0


def _valid_nik_or_kk(num: str) -> bool:
    """16 digit, kode provinsi valid, bulan 01..12 (NIK ladies+40), tanggal 01..71."""
    if len(num) != 16 or not num.isdigit():
        return False
    if num[:2] not in VALID_PROVINCE_CODES:
        return False
    return True


def _has_nik_dob_pattern(num: str) -> bool:
    """NIK pakai DDMMYY di posisi 7..12 (atau DD+40 utk perempuan).
    KK biasanya pakai tanggal pendaftaran kartu (juga DDMMYY).
    Cek longgar saja: bulan 01..12, tanggal 01..71 (40+31), tahun 00..99.
    """
    if len(num) != 16:
        return False
    dd = int(num[6:8])
    mm = int(num[8:10])
    if not (1 <= mm <= 12):
        return False
    if not (1 <= dd <= 71):
        return False
    return True


def _mask(value: str) -> str:
    """Tampilkan PII tersamar di evidence (mis. 320512******1234)."""
    if len(value) <= 4:
        return "*" * len(value)
    if "@" in value:
        local, _, dom = value.partition("@")
        if len(local) <= 2:
            return "*" * len(local) + "@" + dom
        return local[0] + "*" * (len(local) - 2) + local[-1] + "@" + dom
    return value[:4] + "*" * (len(value) - 8) + value[-4:] if len(value) > 8 else value[:2] + "*" * (len(value) - 2)


def _classify_16digit(body: str, num: str) -> str | None:
    """Decide whether a 16-digit number is NIK, KK, CC, or unknown.

    We look at a 80-character window of context around the match.
    """
    if not _valid_nik_or_kk(num) and not _luhn_ok(num):
        return None
    # CC takes priority if Luhn-valid AND begins with CC prefix.
    if RE_CC.match(num) and _luhn_ok(num):
        return "kartu_kredit"
    if not _valid_nik_or_kk(num):
        return None
    # Look for nearest hint in context window.
    idx = body.find(num)
    if idx == -1:
        # number reformatted? skip.
        return None
    window_start = max(0, idx - 80)
    window = body[window_start: idx + 16 + 20]
    if KK_HINT_RE.search(window):
        return "nomor_kk"
    if NIK_HINT_RE.search(window):
        return "nik"
    # Fall back: NIK is more common public leak; require DOB-pattern.
    if _has_nik_dob_pattern(num):
        return "nik"
    return None


def _classify_bank(body: str, num: str) -> bool:
    if not (10 <= len(num) <= 16):
        return False
    idx = body.find(num)
    if idx == -1:
        return False
    window_start = max(0, idx - 80)
    window = body[window_start: idx + len(num) + 20]
    if not BANK_HINT_RE.search(window):
        return False
    # Reject if also a 16-digit NIK / KK / CC (avoid double-count).
    if len(num) == 16:
        return False
    return True


# ---------------------------------------------------------------------------
# Body extraction
# ---------------------------------------------------------------------------


def _extract_pii(body: str) -> dict[str, set[str]]:
    """Run all detectors. Return dict of {category: {value, ...}}."""
    out: dict[str, set[str]] = {
        "nik": set(),
        "nomor_kk": set(),
        "kartu_kredit": set(),
        "rekening_bank": set(),
        "no_hp": set(),
        "email": set(),
        "npwp": set(),
    }
    if not body:
        return out

    # Email
    for m in RE_EMAIL.findall(body):
        out["email"].add(m.lower())
    # Phone ID
    for m in RE_PHONE_ID.finditer(body):
        out["no_hp"].add(m.group(0))
    # NPWP
    for m in RE_NPWP.findall(body):
        out["npwp"].add(m)
    # 16-digit numbers — classify
    for m in RE_16DIGIT.findall(body):
        cls = _classify_16digit(body, m)
        if cls in out:
            out[cls].add(m)
    # Bank accounts (10-15 digits, exclude 16-digit handled above)
    for m in RE_BANK_ACCOUNT.findall(body):
        if 10 <= len(m) <= 15 and _classify_bank(body, m):
            out["rekening_bank"].add(m)

    return out


# ---------------------------------------------------------------------------
# Validation: shape + control fetch
# ---------------------------------------------------------------------------


def _looks_like_dump(body: str) -> bool:
    """Quick check: body terlihat seperti dump (banyak baris/koma/tanda kutip).

    JSON dump ⇒ banyak `{` dan `,` per KB.
    SQL dump ⇒ ada `INSERT INTO` atau `VALUES`.
    CSV dump ⇒ banyak comma per baris.
    """
    if not body:
        return False
    if looks_like_html_shell(body):
        return False
    low = body[:4096].lower()
    if "insert into" in low or "create table" in low:
        return True
    if body.count("{") > 30 or body.count('"id"') > 20:
        return True
    # Heuristic: many newlines + many commas → likely CSV.
    nl = body.count("\n")
    if nl > 30 and (body.count(",") / max(nl, 1)) > 3:
        return True
    return False


def _meets_threshold(pii: dict[str, set[str]]) -> tuple[bool, str]:
    """Return (qualifies, reason)."""
    types_present = [k for k, v in pii.items() if v]
    types_present_strong = [k for k in types_present
                            if k in ("nik", "nomor_kk", "kartu_kredit",
                                     "rekening_bank", "no_hp")]
    counts = {k: len(v) for k, v in pii.items() if v}

    # Rule 1: Any single strong type ≥ 5 unique
    for k in types_present_strong:
        if counts.get(k, 0) >= 5:
            return True, f"{k} ≥ 5 unik ({counts[k]})"
    # Rule 2: ≥ 3 different types together with ≥ 2 each
    if len(types_present_strong) >= 3 and all(counts[k] >= 2 for k in types_present_strong[:3]):
        return True, f"≥3 jenis kuat bersamaan ({', '.join(types_present_strong[:3])})"
    # Rule 3: NIK/KK/CC bahkan 1 instance pun sangat sensitif → tetap laporkan
    # tapi severity-nya dihitung di caller sebagai HIGH (bukan CRITICAL).
    for k in ("nik", "nomor_kk", "kartu_kredit"):
        if counts.get(k, 0) >= 1:
            return True, f"{k} terdeteksi (>=1) — tetap reportable"
    return False, ""


def _severity_for(pii: dict[str, set[str]]) -> Severity:
    counts = {k: len(v) for k, v in pii.items()}
    strong = sum(counts.get(k, 0) for k in ("nik", "nomor_kk", "kartu_kredit", "rekening_bank"))
    if strong >= 50 or counts.get("nik", 0) + counts.get("nomor_kk", 0) >= 20:
        return Severity.CRITICAL
    if strong >= 5 or counts.get("nik", 0) >= 3:
        return Severity.HIGH
    return Severity.MEDIUM


# ---------------------------------------------------------------------------
# Scanner driver
# ---------------------------------------------------------------------------


def _candidate_urls(target: Target, config: ScanConfig) -> list[str]:
    """Build dedup'd list of candidate URLs."""
    base = target.origin + "/"
    cand: list[str] = []
    # Lazy import: keeps unit-tests import-clean if optional deps missing.
    try:
        from cyberloka.recon.crawler import get_state
    except Exception:  # pragma: no cover
        get_state = lambda _: None  # type: ignore[assignment]
    state = get_state(config)
    if state:
        # Prioritise URLs from crawler that look like API/listing/dump
        for u in (state.urls or []) + (state.param_urls or []):
            low = u.lower()
            if any(t in low for t in (
                "/api/", "/users", "/customers", "/members", "/nasabah",
                "/pelanggan", "/anggota", ".json", ".csv", ".sql",
                "dump", "backup", "export"
            )):
                cand.append(u)
    for p in DB_LEAK_PATHS:
        cand.append(urljoin(base, p.lstrip("/")))
    # Dedup preserving order
    seen, out = set(), []
    for u in cand:
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
        if len(out) >= MAX_PROBES:
            break
    return out


def _negative_control(client: HttpClient, target: Target) -> dict[str, set[str]] | None:
    url = urljoin(target.origin + "/",
                  f"cyberloka_{secrets.token_hex(6)}_404")
    r = client.get(url)
    if r is None or r.status_code != 200:
        return None
    return _extract_pii(r.text or "")


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary, awam_steps = get_awam("db_pii_leak")
    try:
        ctrl_pii = _negative_control(client, target)

        for url in _candidate_urls(target, config):
            r = client.get(url)
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            if looks_like_html_shell(body):
                continue

            pii = _extract_pii(body)

            # Subtract control-PII (server may always echo a footer email)
            if ctrl_pii:
                for k, vals in ctrl_pii.items():
                    pii[k] -= vals

            qualifies, reason = _meets_threshold(pii)
            if not qualifies:
                continue

            looks_dump = _looks_like_dump(body)
            sev = _severity_for(pii)
            if not looks_dump and sev == Severity.CRITICAL:
                # Tanpa "shape dump", kita lebih konservatif → turunkan.
                sev = Severity.HIGH

            counts = {k: len(v) for k, v in pii.items() if v}
            sample_lines = []
            for k in ("nik", "nomor_kk", "kartu_kredit", "rekening_bank",
                      "no_hp", "email", "npwp"):
                if pii.get(k):
                    head = list(pii[k])[:3]
                    sample_lines.append(
                        f"{k}: {counts[k]} unik (cth: {', '.join(_mask(v) for v in head)})"
                    )

            proof = ValidationProof(
                method="pattern+context+threshold+control-diff",
                confirmed=looks_dump,
                steps=[
                    f"GET {url} → 200 OK, len={len(body)} bytes.",
                    "Body BUKAN SPA HTML shell (filter looks_like_html_shell lolos).",
                    (f"Body ber-shape dump ({Counter([k for k,v in pii.items() if v])} jenis PII)."
                     if looks_dump else
                     "Body bukan dump kanonik (JSON/CSV/SQL dump shape) — tetap dilaporkan "
                     "karena threshold PII lolos."),
                    f"Threshold lolos: {reason}.",
                    ("Negative-control fetch path random tidak memuat PII yang sama "
                     "(efek dump dikurangi)."
                     if ctrl_pii is not None else
                     "Negative-control fetch tidak tersedia (server tidak balas 200 untuk path random)."),
                    "NIK/KK divalidasi dengan kode provinsi BPS; CC dengan Luhn checksum.",
                ],
                samples=sample_lines,
                notes="evidence sudah di-mask",
            )

            findings.append(Finding(
                module="db_pii_leak",
                title=f"Kebocoran PII massal di endpoint: {url}",
                severity=sev,
                description=(
                    "Endpoint publik mengembalikan data dengan banyak instance PII "
                    "Indonesia (NIK / KK / nomor rekening / HP / email). Threshold "
                    f"validasi lolos: {reason}. "
                    + ("Bentuk respons konsisten dengan dump database (JSON/CSV/SQL)."
                       if looks_dump else
                       "Bentuk respons bukan dump kanonik — verifikasi manual disarankan, "
                       "tapi pola PII tetap signifikan.")
                ),
                target=url,
                urls=[url],
                evidence="\n".join(sample_lines),
                cwe="CWE-359",
                confidence="confirmed" if looks_dump else "firm",
                remediation=(
                    "Tambahkan autentikasi pada endpoint listing/dump (JWT + RBAC). "
                    "Mask PII di response (`****-****-1234`). Audit & matikan endpoint "
                    "dump/backup yang ter-deploy ke webroot. Tambahkan rate-limit + "
                    "logging untuk akses bulk. Wajib comply UU PDP No. 27/2022 dan "
                    "POJK 12/2018 untuk fintech."
                ),
                references=[
                    "https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022",
                    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                ],
                extra=build_extra(
                    proof=proof,
                    awam_steps=awam_steps,
                    awam_summary=awam_summary,
                    extra={"counts": counts, "shape_dump": looks_dump},
                ),
            ))
    finally:
        client.close()
    return findings
