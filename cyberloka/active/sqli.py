"""SQL Injection — verification-first (error muncul→hilang + boolean differential).

Masalah pendekatan lama:
  - Error-based mencari signature SQL di satu respons → halaman dokumentasi yang
    memuat teks error dianggap rentan.
  - Boolean-based hanya beda panjang > 200 byte → konten dinamis memicu palsu.

Pendekatan baru:
  - Error-based: baseline harus BERSIH, petik tunggal MEMUNCULKAN error, petik
    diseimbangkan MENGHILANGKAN-nya (pola muncul→hilang = input masuk ke sintaks SQL).
  - Boolean-based: `1=1` ≈ baseline DAN `1=2` berbeda nyata, pada 2 konteks.
"""
from __future__ import annotations

import re

from cyberloka.active._helpers import (
    candidate_urls,
    fetch,
    fuzz_forms,
    get_param_value,
    param_names,
    replace_param,
    similarity,
)
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

ERROR_SIGNATURES = [
    r"sql syntax.*mysql",
    r"warning.*\bmysqli?\b",
    r"valid mysql result",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlstate\[",
    r"odbc.*sql server",
    r"microsoft sql native client",
    r"pg::syntaxerror",
    r"postgresql.*error",
    r"sqlite3?::",
    r"unrecognized token",
    r"oracle.*ora-\d{4,}",
    r"you have an error in your sql syntax",
]
ERROR_RE = re.compile("|".join(ERROR_SIGNATURES), re.I)

SIMILAR = 0.95
DIFFERENT = 0.95


def _sqli_finding(param: str, target_url: str, sig: str, ev: str, is_form: bool) -> Finding:
    where = f"field form `{param}`" if is_form else f"parameter `{param}`"
    return Finding(
        module="sqli",
        title=f"SQL Injection TERVERIFIKASI ({sig}) pada {where}",
        severity=Severity.CRITICAL,
        confidence="confirmed",
        description=(
            "Aplikasi terbukti mengeksekusi SQL yang disuntikkan (pola error muncul→hilang "
            "atau respons boolean true≈baseline / false berbeda). SQL Injection memungkinkan "
            "attacker membaca/menulis seluruh database."
        ),
        target=target_url,
        evidence=ev,
        cwe="CWE-89",
        remediation=(
            "Gunakan parameterized query / prepared statements. JANGAN concatenate input ke query. "
            "Untuk ORM hindari raw SQL dengan input user. Tambahkan validasi tipe + WAF."
        ),
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    )


def _error_based(client: HttpClient, url: str, param: str, base_body: str) -> str | None:
    if ERROR_RE.search(base_body or ""):
        return None
    val = get_param_value(url, param) or "1"
    broke = fetch(client, replace_param(url, param, val + "'"))
    if broke is None:
        return None
    m = ERROR_RE.search(broke.text)
    if not m:
        return None
    # Kontrol: suffix benign TANPA karakter quote tidak boleh memunculkan error.
    # Membuktikan error dipicu oleh quote yang memecah konteks string SQL — bukan
    # oleh input "mencurigakan" apa pun (mis. WAF/halaman error generik).
    control = fetch(client, replace_param(url, param, val + "abc123"))
    if control is None or ERROR_RE.search(control.text):
        return None
    return truncate(m.group(0), 120)


def _boolean_based(client: HttpClient, url: str, param: str, base_text: str) -> str | None:
    val = get_param_value(url, param) or "1"
    contexts = [
        (f"{val} AND 1=1-- -", f"{val} AND 1=2-- -"),
        (f"{val}' AND '1'='1", f"{val}' AND '1'='2"),
    ]
    confirmed, evidences = 0, []
    for true_p, false_p in contexts:
        rt = fetch(client, replace_param(url, param, true_p))
        rf = fetch(client, replace_param(url, param, false_p))
        if rt is None or rf is None:
            continue
        s_tb = similarity(base_text, rt.text)
        s_tf = similarity(rt.text, rf.text)
        if s_tb >= SIMILAR and s_tf < DIFFERENT:
            confirmed += 1
            evidences.append(f"sim(true,baseline)={s_tb:.2f} sim(true,false)={s_tf:.2f}")
    if confirmed and evidences:
        tag = "2 konteks" if confirmed >= 2 else "1 konteks"
        return f"{tag}: " + " | ".join(evidences)
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for scan_url in candidate_urls(target, config, "id", "1"):
            base = fetch(client, scan_url)
            if base is None:
                continue
            for param in param_names(scan_url):
                ev = _error_based(client, scan_url, param, base.text)
                if ev:
                    findings.append(_sqli_finding(param, scan_url, "error-based", ev, is_form=False))
                    continue
                ev = _boolean_based(client, scan_url, param, base.text)
                if ev:
                    findings.append(_sqli_finding(param, scan_url, "boolean-based", ev, is_form=False))

        # Form: error harus dipicu oleh QUOTE, bukan input apa pun. Submit benign
        # (tanpa quote) lalu submit quote; lapor hanya (action,field) yang error pada
        # quote TAPI bersih pada benign.
        benign_error: set[tuple[str, str]] = set()
        for field, action, resp in fuzz_forms(client, config, "benign123"):
            if ERROR_RE.search(resp.text or ""):
                benign_error.add((action, field))
        for field, action, resp in fuzz_forms(client, config, "benign123'"):
            m = ERROR_RE.search(resp.text or "")
            if m and (action, field) not in benign_error:
                findings.append(_sqli_finding(field, action, "error-based", truncate(m.group(0), 120), is_form=True))
    finally:
        client.close()
    return findings
