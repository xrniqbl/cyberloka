"""Validasi .git/.svn repository dapat di-dump (path traversal style).

Bedanya dengan sensitive_files (yang hanya cek HTTP 200), modul ini benar-benar
parse konten /.git/HEAD dan /.git/config supaya yakin file tersebut adalah file
git asli (bukan halaman 200 placeholder dari SPA fallback).

Kalau berhasil parse:
  - Catat branch yang aktif (HEAD ref)
  - Catat remote URL kalau ada di config (membocorkan kredensial git!)
  - Konfirmasi /.git/index dapat dibaca (binary signature DIRC)
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

GIT_HEAD_RE = re.compile(rb"^\s*ref:\s*refs/heads/[\w./-]+\s*$|^\s*[0-9a-f]{40}\s*$", re.M)
GIT_INDEX_SIG = b"DIRC"


def _check_git(client: HttpClient, base: str) -> dict | None:
    """Validate .git/ exposure. Return dict of evidence or None."""
    out: dict = {}
    head = client.get(urljoin(base, ".git/HEAD"))
    if head is None or head.status_code != 200:
        return None
    head_body = head.content or b""
    if not GIT_HEAD_RE.search(head_body):
        return None
    out["head"] = head_body[:200].decode("latin-1", errors="replace").strip()

    cfg = client.get(urljoin(base, ".git/config"))
    if cfg is not None and cfg.status_code == 200:
        text = cfg.text or ""
        if "[core]" in text or "[remote " in text:
            out["config"] = text[:500]
            # Cari remote URL (kemungkinan ada credential)
            remotes = re.findall(r'url\s*=\s*([^\s\n]+)', text)
            if remotes:
                out["remotes"] = remotes
                # Detect cred dalam URL
                if any(re.search(r"://[^/]+:[^@]+@", u) for u in remotes):
                    out["credentials_in_url"] = True

    idx = client.get(urljoin(base, ".git/index"))
    if idx is not None and idx.status_code == 200 and (idx.content or b"")[:4] == GIT_INDEX_SIG:
        out["index_dumpable"] = True

    pack = client.get(urljoin(base, ".git/info/refs?service=git-upload-pack"))
    if pack is not None and pack.status_code == 200 and "service=git-upload-pack" in (pack.text or ""):
        out["smart_http"] = True

    return out


def _check_svn(client: HttpClient, base: str) -> dict | None:
    out: dict = {}
    entries = client.get(urljoin(base, ".svn/entries"))
    if entries is not None and entries.status_code == 200:
        body = entries.text or ""
        if body.strip().startswith("12") or "svn://" in body or "<entry" in body:
            out["entries"] = body[:200]
    wcdb = client.get(urljoin(base, ".svn/wc.db"))
    if wcdb is not None and wcdb.status_code == 200 and (wcdb.content or b"")[:15] == b"SQLite format 3":
        out["wcdb_sqlite"] = True
    return out or None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.base_url
    client = HttpClient(config)
    try:
        git = _check_git(client, base)
        if git:
            sev = Severity.CRITICAL if git.get("credentials_in_url") else Severity.HIGH
            ev = [f"URL .git/HEAD: {urljoin(base, '.git/HEAD')}", f"HEAD content: {git['head']}"]
            if "config" in git:
                ev.append(f"config snippet:\n{git['config']}")
            if git.get("remotes"):
                ev.append(f"remotes: {git['remotes']}")
            if git.get("credentials_in_url"):
                ev.append("!! CREDENTIALS IN REMOTE URL DETECTED !!")
            if git.get("index_dumpable"):
                ev.append(".git/index dapat di-download (DIRC signature OK)")
            if git.get("smart_http"):
                ev.append(".git/info/refs aktif (smart HTTP) - bisa pakai `git clone <base>/.git`")
            findings.append(Finding(
                module="git_repo_dump",
                target=urljoin(base, ".git/"),
                title=(
                    ".git repository dapat di-dump"
                    + (" (kredensial git ditemukan di config)" if git.get("credentials_in_url") else "")
                ),
                severity=sev,
                description=(
                    "Folder .git dapat diakses publik. Modul sudah memvalidasi via "
                    "parse .git/HEAD (regex match), config (section [core]/[remote]), "
                    "dan index (DIRC signature). Ini bukan false positive 200-page-fallback."
                    + (
                        " Selain itu, terdeteksi kredensial inline di URL remote "
                        "(format protocol://user:pass@host) - sangat kritikal, attacker "
                        "punya akses langsung ke repo."
                        if git.get("credentials_in_url") else ""
                    )
                    + " Attacker bisa: `wget -r {base}/.git/` lalu `git clone .git/ ./loot` "
                    "untuk dapat seluruh source code, history commit (termasuk secret "
                    "yang sempat di-commit lalu dihapus)."
                ).replace("{base}", base.rstrip("/")),
                evidence="\n".join(ev),
                cwe="CWE-538",
                confidence="confirmed",
                urls=[urljoin(base, ".git/HEAD"), urljoin(base, ".git/config")],
                remediation=(
                    "1. WAJIB block /.git/ dan /.svn/ di nginx/.htaccess (return 404).\n"
                    "   nginx: `location ~ /\\.git { deny all; return 404; }`\n"
                    "2. Jangan deploy via `git clone` ke webroot. Pakai CI/CD atau rsync\n"
                    "   yang exclude .git.\n"
                    "3. Bila kredensial git bocor: rotate token IMMEDIATELY + audit semua\n"
                    "   commit untuk secret yang ter-leak."
                ),
                references=[
                    "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
                    "https://github.com/internetwache/GitTools",
                ],
            ))

        svn = _check_svn(client, base)
        if svn:
            ev = []
            if "entries" in svn:
                ev.append(f"entries snippet: {svn['entries']}")
            if svn.get("wcdb_sqlite"):
                ev.append(".svn/wc.db is SQLite (downloadable)")
            findings.append(Finding(
                module="git_repo_dump",
                target=urljoin(base, ".svn/"),
                title=".svn repository dapat di-dump (full source code leak)",
                severity=Severity.HIGH,
                description=(
                    "Folder .svn terbuka publik. Modul memvalidasi via konten "
                    ".svn/entries (format SVN versi 1.7+) dan .svn/wc.db (SQLite "
                    "signature). Attacker bisa rebuild seluruh source code dari sini."
                ),
                evidence="\n".join(ev),
                cwe="CWE-538",
                confidence="confirmed",
                urls=[urljoin(base, ".svn/entries")],
                remediation="Block /.svn/ di nginx/.htaccess. Pakai CI/CD untuk deploy.",
            ))
    finally:
        client.close()
    return findings
