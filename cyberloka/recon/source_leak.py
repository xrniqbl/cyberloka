"""Probe source-control & build artifact leaks."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

LEAK_PATHS = [
    (".git/HEAD", "git repo", Severity.CRITICAL,
     re.compile(r"^ref:\s*refs/heads/", re.I)),
    (".git/config", "git config", Severity.CRITICAL,
     re.compile(r"\[core\]", re.I)),
    (".gitignore", "gitignore", Severity.LOW, None),
    (".svn/entries", "svn repo", Severity.HIGH, None),
    (".hg/store/00manifest.i", "mercurial repo", Severity.HIGH, None),
    (".env", "env file", Severity.CRITICAL,
     re.compile(r"^[A-Z_]+\s*=", re.M)),
    (".env.production", "env file (prod)", Severity.CRITICAL,
     re.compile(r"^[A-Z_]+\s*=", re.M)),
    (".env.local", "env file", Severity.CRITICAL, None),
    ("composer.json", "composer manifest", Severity.LOW, None),
    ("composer.lock", "composer lockfile", Severity.MEDIUM, None),
    ("package.json", "npm manifest", Severity.LOW, None),
    ("package-lock.json", "npm lockfile", Severity.LOW, None),
    ("yarn.lock", "yarn lockfile", Severity.LOW, None),
    ("Dockerfile", "Dockerfile", Severity.MEDIUM, None),
    ("docker-compose.yml", "docker-compose", Severity.MEDIUM, None),
    (".DS_Store", "macOS metadata", Severity.LOW, None),
    ("backup.sql", "SQL dump", Severity.CRITICAL, None),
    ("dump.sql", "SQL dump", Severity.CRITICAL, None),
    ("config.php.bak", "PHP config backup", Severity.HIGH, None),
    ("wp-config.php.bak", "WP config backup", Severity.CRITICAL, None),
    ("id_rsa", "SSH private key", Severity.CRITICAL, None),
    (".aws/credentials", "AWS credentials", Severity.CRITICAL, None),
    ("phpinfo.php", "phpinfo()", Severity.HIGH, re.compile(r"PHP Version", re.I)),
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    base = target.origin + "/"
    try:
        for path, label, sev, content_re in LEAK_PATHS:
            url = urljoin(base, path)
            r = client.get(url)
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            ctype = r.headers.get("Content-Type", "").lower()
            # Halaman 200 bisa "soft 404" — verifikasi via konten
            if content_re and not content_re.search(body):
                continue
            if not content_re and ("text/html" in ctype and "<html" in body.lower()
                                   and "404" in body.lower()):
                continue
            findings.append(Finding(
                module="source_leak",
                title=f"Resource sensitif terbuka publik: {path} ({label})",
                severity=sev,
                description=(f"File {label} dapat diakses tanpa autentikasi. "
                             "Jika benar berisi data nyata, attacker bisa memperoleh "
                             "kredensial/source code/struktur internal."),
                target=url,
                evidence=truncate(body, 200),
                cwe="CWE-538",
                remediation=("Tolak akses ke file/folder dot (`.git`, `.env`, `.svn`) di "
                             "web server (`location ~ /\\. { deny all; }` di nginx). "
                             "Jangan deploy file dev/backup ke produksi."),
            ))
    finally:
        client.close()
    return findings
