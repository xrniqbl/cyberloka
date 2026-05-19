"""Probe source-control & build artifact leaks — strict-validation v0.10.1.

Setiap finding di sini sangat sensitif (kalau benar = akses kunci/source).
Karena itu kami WAJIB validate dengan content-signature + content-type
shape filter — tidak hanya status 200.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
    content_type_is_text_data,
    looks_like_html_shell,
)
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.reporting.awam import get_awam

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
    (".env.local", "env file", Severity.CRITICAL,
     re.compile(r"^[A-Z_]+\s*=", re.M)),
    ("composer.json", "composer manifest", Severity.LOW,
     re.compile(r'"require"\s*:|"name"\s*:', re.I)),
    ("composer.lock", "composer lockfile", Severity.MEDIUM,
     re.compile(r'"_readme"|"packages"', re.I)),
    ("package.json", "npm manifest", Severity.LOW,
     re.compile(r'"dependencies"\s*:|"name"\s*:', re.I)),
    ("package-lock.json", "npm lockfile", Severity.LOW,
     re.compile(r'"lockfileVersion"', re.I)),
    ("yarn.lock", "yarn lockfile", Severity.LOW,
     re.compile(r"^# yarn lockfile", re.I)),
    ("Dockerfile", "Dockerfile", Severity.MEDIUM,
     re.compile(r"^FROM\s+\S+", re.I | re.M)),
    ("docker-compose.yml", "docker-compose", Severity.MEDIUM,
     re.compile(r"^version:|^services:", re.M)),
    ("backup.sql", "SQL dump", Severity.CRITICAL,
     re.compile(r"INSERT INTO|CREATE TABLE", re.I)),
    ("dump.sql", "SQL dump", Severity.CRITICAL,
     re.compile(r"INSERT INTO|CREATE TABLE", re.I)),
    ("config.php.bak", "PHP config backup", Severity.HIGH,
     re.compile(r"<\?php|define\(|\$config", re.I)),
    ("wp-config.php.bak", "WP config backup", Severity.CRITICAL,
     re.compile(r"DB_PASSWORD|DB_NAME", re.I)),
    ("id_rsa", "SSH private key", Severity.CRITICAL,
     re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    (".aws/credentials", "AWS credentials", Severity.CRITICAL,
     re.compile(r"\[default\]|aws_access_key_id", re.I)),
    ("phpinfo.php", "phpinfo()", Severity.HIGH,
     re.compile(r"PHP Version", re.I)),
]


def _control_returns_signature(client, base: str, path: str,
                                content_re) -> bool:
    """Detect server that ignores 404 and serves the same body for any path."""
    if content_re is None:
        return False
    rand_path = path.rsplit("/", 1)[0]
    if rand_path:
        rand_path += "/"
    rand_path += f"cyberloka_{secrets.token_hex(4)}"
    url = urljoin(base, rand_path)
    r = client.get(url)
    if r is None or r.status_code != 200:
        return False
    return bool(content_re.search(r.text or ""))


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    base = target.origin + "/"
    awam_summary, awam_steps = get_awam("source_leak")
    try:
        for path, label, sev, content_re in LEAK_PATHS:
            url = urljoin(base, path)
            r = client.get(url)
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            ctype = r.headers.get("Content-Type", "").lower()

            if looks_like_html_shell(body):
                continue

            if content_re:
                if not content_re.search(body):
                    continue
                if _control_returns_signature(client, base, path, content_re):
                    continue
            else:
                if "text/html" in ctype and "<html" in body.lower():
                    if "404" in body.lower() or "not found" in body.lower():
                        continue
                    if not content_type_is_text_data(ctype):
                        continue

            sig_text = (
                content_re.search(body).group(0) if content_re else f"path={path}"
            )
            proof = ValidationProof(
                method="signature+control-fetch",
                confirmed=True,
                steps=[
                    f"GET {url} → 200 OK, content-type={ctype or 'n/a'}.",
                    "Body BUKAN SPA shell (filter looks_like_html_shell lolos).",
                    (f"Body memuat signature kanonik: `{truncate(sig_text, 60)}`."
                     if content_re else
                     "Path itu sendiri sudah cukup spesifik (mis. id_rsa, .DS_Store)."),
                    ("Kontrol fetch path random pada folder yang sama TIDAK "
                     "mengembalikan signature yang sama."
                     if content_re else
                     "Tidak ada control fetch karena tidak ada regex signature."),
                ],
                samples=[truncate(body, 200)],
                notes=f"path={path}, label={label}, sev={sev.value}",
            )

            findings.append(Finding(
                module="source_leak",
                title=f"Resource sensitif terbuka publik: {path} ({label})",
                severity=sev,
                description=(f"File {label} dapat diakses tanpa autentikasi dan kontennya "
                             "konsisten dengan tipe file aslinya (sudah divalidasi). "
                             "Attacker bisa memperoleh kredensial / source code / "
                             "struktur internal langsung dari URL ini."),
                target=url,
                evidence=truncate(body, 200),
                cwe="CWE-538",
                confidence="confirmed" if content_re else "firm",
                urls=[url],
                remediation=("Tolak akses ke file/folder dot (`.git`, `.env`, `.svn`) di "
                             "web server (`location ~ /\\. { deny all; }` di nginx). "
                             "Jangan deploy file dev/backup ke produksi."),
                extra=build_extra(
                    proof=proof,
                    awam_steps=awam_steps,
                    awam_summary=awam_summary,
                ),
            ))
    finally:
        client.close()
    return findings
