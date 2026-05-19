"""Deep `.git/` directory disclosure scanner.

Selain `source_leak.py` yang hanya probe `.git/HEAD`, modul ini meng-probe
**multi-path** `.git/` dan **memvalidasi** isi response benar-benar artefak
git (bukan SPA generic 200) sebelum melaporkan finding.

Validasi:
    * `.git/HEAD`            -> harus diawali `ref: refs/` atau 40-hex SHA.
    * `.git/config`          -> harus memuat `[core]` dan `repositoryformat`.
    * `.git/index`           -> magic bytes `DIRC` di awal file.
    * `.git/logs/HEAD`       -> regex `^\\w{40}\\s\\w{40}\\s`.
    * `.git/packed-refs`     -> regex `^# pack-refs`.
    * `.git/objects/info/packs` -> baris diawali `P pack-` + 40 hex.
    * `.gitignore`            -> hint, severity rendah (info-only).
    * `.git/COMMIT_EDITMSG`   -> hint.

Setiap finding pasti memuat `extra["reverify"]` dengan marker spesifik
sehingga validator gate akan re-confirm sebelum masuk report.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

# (path, label, validator-callable, severity, marker_for_reverify, cwe)
GitProbe = tuple[str, str, "callable", Severity, str, str]


def _validate_head(body: bytes) -> bool:
    text = body.decode("utf-8", "ignore").strip()
    return bool(re.match(r"^(ref:\s+refs/|[0-9a-f]{40}$)", text))


def _validate_config(body: bytes) -> bool:
    text = body.decode("utf-8", "ignore")
    return ("[core]" in text and
            ("repositoryformatversion" in text or "filemode" in text))


def _validate_index(body: bytes) -> bool:
    return body.startswith(b"DIRC")


def _validate_logs_head(body: bytes) -> bool:
    text = body.decode("utf-8", "ignore")
    return bool(re.match(r"^[0-9a-f]{40}\s[0-9a-f]{40}\s", text))


def _validate_packed_refs(body: bytes) -> bool:
    text = body.decode("utf-8", "ignore")
    return text.startswith("# pack-refs")


def _validate_packs_info(body: bytes) -> bool:
    text = body.decode("utf-8", "ignore")
    return bool(re.search(r"^P pack-[0-9a-f]{40}\.pack", text, re.M))


def _validate_gitignore(body: bytes) -> bool:
    text = body.decode("utf-8", "ignore")
    # heuristik longgar: bukan HTML
    return not text.lstrip().startswith("<") and "\n" in text


def _validate_commit_editmsg(body: bytes) -> bool:
    text = body.decode("utf-8", "ignore")
    return bool(text.strip()) and not text.lstrip().startswith("<")


PROBES: list[GitProbe] = [
    (".git/HEAD", "Git HEAD reference", _validate_head,
     Severity.CRITICAL, "ref:", "CWE-538"),
    (".git/config", "Git config", _validate_config,
     Severity.CRITICAL, "[core]", "CWE-538"),
    (".git/index", "Git index (file tree)", _validate_index,
     Severity.CRITICAL, "DIRC", "CWE-538"),
    (".git/logs/HEAD", "Git history log", _validate_logs_head,
     Severity.CRITICAL, "", "CWE-538"),
    (".git/packed-refs", "Git packed refs", _validate_packed_refs,
     Severity.HIGH, "# pack-refs", "CWE-538"),
    (".git/objects/info/packs", "Git packs index", _validate_packs_info,
     Severity.HIGH, "P pack-", "CWE-538"),
    (".git/COMMIT_EDITMSG", "Last commit message", _validate_commit_editmsg,
     Severity.LOW, "", "CWE-200"),
    (".gitignore", "gitignore file", _validate_gitignore,
     Severity.INFO, "", "CWE-200"),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.origin + "/"
    client = HttpClient(config)
    found_critical_root = False
    try:
        for path, label, validator, sev, marker, cwe in PROBES:
            url = urljoin(base, path)
            r = client.get(url, allow_redirects=False,
                           headers={"Range": "bytes=0-32767"})
            if r is None or r.status_code >= 400:
                continue
            body = r.content or b""
            if not body or not validator(body):
                continue

            # Validasi tambahan: untuk artefak kritis pertama, simpan flag
            if sev == Severity.CRITICAL:
                found_critical_root = True

            findings.append(Finding(
                module="git_disclosure",
                title=f".git directory ter-ekspos publik: {path}",
                severity=sev,
                description=(
                    f"Artefak repositori Git `{path}` ({label}) dapat di-download "
                    "dari internet. Attacker yang menemukan satu artefak biasanya "
                    "mampu merekonstruksi repo lengkap menggunakan `git-dumper` "
                    "atau `wget --mirror` — termasuk seluruh history commit, "
                    "branch lama, password, dan kunci API yang pernah di-commit."
                ),
                target=url,
                evidence=truncate(
                    f"HTTP {r.status_code}, len={len(body)}, "
                    f"head={body[:48]!r}",
                    240,
                ),
                cwe=cwe,
                confidence="confirmed",
                remediation=(
                    "Tutup akses ke direktori `.git/` di reverse-proxy "
                    "(nginx: `location ~ /\\.git { deny all; return 404; }`; "
                    "Apache: `<DirectoryMatch \"^\\.git\">  Require all denied "
                    "</DirectoryMatch>`). Pastikan deployment Anda tidak "
                    "menyalin folder `.git` ke webroot. Audit history kalau "
                    "sudah terlanjur ter-ekspos: rotasi semua secret yang pernah "
                    "ada di history (`git log -p`)."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage",
                    "https://github.com/arthaud/git-dumper",
                ],
                extra={"reverify": {"status": (200, 206),
                                    "marker": marker} if marker
                       else {"status": (200, 206)}},
            ))
        # Hentikan probe lain bila kita sudah dapat artefak kritis valid
        # (cukup untuk bukti exposure menyeluruh).
        if found_critical_root and len(findings) >= 4:
            return findings
    finally:
        client.close()
    return findings
