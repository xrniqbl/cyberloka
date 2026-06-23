"""Sensitive file exposure scanner — strict-validation v0.10.1.

Untuk hindari "200 catch-all SPA → false positive", kita:
  * Bandingkan response path target dengan response path RANDOM (control).
    Kalau panjang & content-type identik → server selalu balas hal yang sama
    untuk path apa pun → reject finding.
  * Kalau path mengandung `.env`, `.git/`, `id_rsa`, `wp-config`, dst.
    laporan tetap CRITICAL TAPI confidence diturunkan ke ``firm`` bila
    body terlihat sebagai HTML SPA generik.
"""
from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
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
from cyberloka.core.util import load_data_lines, truncate
from cyberloka.reporting.awam import get_awam


def _check(client: HttpClient, base: str, path: str,
           ctrl_signature: tuple[int, str] | None):
    url = urljoin(base, path)
    resp = client.get(url, allow_redirects=False)
    if resp is None or resp.status_code != 200 or not resp.content:
        return None
    body = resp.text or ""
    ctype = resp.headers.get("Content-Type", "")

    if ctrl_signature is not None:
        c_len, c_first = ctrl_signature
        if abs(len(body) - c_len) <= 16 and body[:64] == c_first[:64]:
            return None

    is_html_shell = looks_like_html_shell(body)
    return url, resp.status_code, f"{ctype} | {truncate(body, 200)}", is_html_shell


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    paths = load_data_lines("sensitive_paths.txt")
    if not paths:
        return findings
    client = HttpClient(config)
    awam_summary, awam_steps = get_awam("sensitive_files")
    try:
        ctrl_url = urljoin(
            target.origin + "/", f"cyberloka_{secrets.token_hex(6)}_404.txt"
        )
        ctrl = client.get(ctrl_url, allow_redirects=False)
        ctrl_sig = None
        if ctrl is not None and ctrl.status_code == 200 and ctrl.content:
            ctrl_sig = (len(ctrl.text or ""), (ctrl.text or "")[:128])

        with ThreadPoolExecutor(max_workers=min(20, config.threads * 2)) as ex:
            futures = [
                ex.submit(_check, client, target.origin + "/", p, ctrl_sig)
                for p in paths
            ]
            for fut in as_completed(futures):
                res = fut.result()
                if not res:
                    continue
                url, status, ev, is_html_shell = res

                lower = url.lower()
                if any(s in lower for s in (".env", ".git/", "id_rsa", "credentials", "wp-config")):
                    sev = Severity.CRITICAL
                elif any(s in lower for s in ("backup", "dump.sql", "database.sql", ".sql")):
                    sev = Severity.HIGH
                elif any(s in lower for s in ("phpinfo", "adminer", "phpmyadmin", "server-status")):
                    sev = Severity.HIGH
                else:
                    sev = Severity.MEDIUM

                confidence = "firm" if is_html_shell else "confirmed"
                proof = ValidationProof(
                    method="status-200+control-diff" + ("+spa-shell-warn" if is_html_shell else ""),
                    confirmed=not is_html_shell,
                    steps=[
                        f"GET {url} → 200.",
                        ("Kontrol path random TIDAK menghasilkan response identik."
                         if ctrl_sig else
                         "Tidak ada control-fetch (kontrol gagal)."),
                        ("Body terlihat seperti SPA HTML shell — verifikasi manual perlu."
                         if is_html_shell else
                         "Body tidak terlihat seperti SPA HTML shell."),
                    ],
                    samples=[truncate(ev, 200)],
                    notes="confidence diturunkan ke 'firm' bila SPA shell",
                )

                findings.append(
                    Finding(
                        module="sensitive_files",
                        title=f"File/path sensitif ter-ekspos: {url}",
                        severity=sev,
                        description=(
                            "Endpoint berikut mengembalikan 200 OK dan berbeda dari "
                            "kontrol path random. Berpotensi memuat informasi sensitif "
                            "(kredensial, source-code, backup, dsb.). Verifikasi manual "
                            "konten file disarankan."
                        ),
                        target=url,
                        urls=[url],
                        evidence=ev,
                        confidence=confidence,
                        remediation=(
                            "Hapus file dari root web atau blokir lewat web server "
                            "(`location ~ /\\.git { deny all; }` di Nginx). Pastikan "
                            "deploy artifact tidak mengikutkan file dev/backup."
                        ),
                        references=[
                            "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                        ],
                        extra=build_extra(
                            proof=proof,
                            awam_steps=awam_steps,
                            awam_summary=awam_summary,
                        ),
                    )
                )
    finally:
        client.close()
    return findings
