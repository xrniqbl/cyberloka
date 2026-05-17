"""Sensitive file exposure scanner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import load_data_lines, truncate


def _check(client: HttpClient, base: str, path: str) -> tuple[str, int, str] | None:
    url = urljoin(base, path)
    resp = client.get(url, allow_redirects=False)
    if resp is None:
        return None
    if resp.status_code == 200 and resp.content:
        ctype = resp.headers.get("Content-Type", "")
        # filter out generic 200 SPA pages by checking small payload markers
        body = resp.text[:512] if resp.text else ""
        return url, resp.status_code, f"{ctype} | {truncate(body, 200)}"
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    paths = load_data_lines("sensitive_paths.txt")
    if not paths:
        return findings
    client = HttpClient(config)
    try:
        with ThreadPoolExecutor(max_workers=min(20, config.threads * 2)) as ex:
            futures = [ex.submit(_check, client, target.origin + "/", p) for p in paths]
            for fut in as_completed(futures):
                res = fut.result()
                if not res:
                    continue
                url, status, ev = res
                # heuristic severity
                lower = url.lower()
                if any(s in lower for s in (".env", ".git/", "id_rsa", "credentials", "wp-config")):
                    sev = Severity.CRITICAL
                elif any(s in lower for s in ("backup", "dump.sql", "database.sql", ".sql")):
                    sev = Severity.HIGH
                elif any(s in lower for s in ("phpinfo", "adminer", "phpmyadmin", "server-status")):
                    sev = Severity.HIGH
                else:
                    sev = Severity.MEDIUM
                findings.append(
                    Finding(
                        module="sensitive_files",
                        title=f"File/path sensitif ter-ekspos: {url}",
                        severity=sev,
                        description=(
                            "Endpoint berikut mengembalikan 200 OK dan berpotensi memuat "
                            "informasi sensitif (kredensial, source-code, backup, dsb.)."
                        ),
                        target=url,
                        evidence=ev,
                        remediation=(
                            "Hapus file dari root web atau blokir lewat web server "
                            "(`location ~ /\\.git { deny all; }` di Nginx). Pastikan "
                            "deploy artifact tidak mengikutkan file dev/backup."
                        ),
                        references=[
                            "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                        ],
                    )
                )
    finally:
        client.close()
    return findings
