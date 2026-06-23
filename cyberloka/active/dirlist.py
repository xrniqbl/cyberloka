"""Directory listing exposure check — strict-validation v0.10.1.

False-positive guards:
  * Title regex tetap dipakai, plus
  * Anchor count >= 3 (real listing has many <a href>).
  * Body bukan SPA shell.
  * Kontrol /<random>/ — tidak boleh ikut listing.
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
    looks_like_html_shell,
)
from cyberloka.core.config import ScanConfig
from cyberloka.reporting.awam import get_awam

CANDIDATE_DIRS = [
    "/", "/uploads/", "/files/", "/static/", "/assets/", "/images/", "/img/",
    "/backup/", "/old/", "/tmp/",
]
TITLE_RE = re.compile(r"<title>\s*Index of\s*/|Directory listing for ", re.I)
HREF_RE = re.compile(r"<a\s+[^>]*href\s*=\s*[\"']", re.I)


def _looks_like_listing(body: str) -> tuple[bool, int]:
    """Return (is_real_listing, anchor_count)."""
    if not body or looks_like_html_shell(body):
        return False, 0
    if not TITLE_RE.search(body):
        return False, 0
    anchor_count = len(HREF_RE.findall(body))
    return anchor_count >= 3, anchor_count


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary, awam_steps = get_awam("dirlist")
    try:
        # Negative control: a directory path that surely doesn't exist —
        # bila server tetap balas 200 dengan listing kanonik, web server
        # bermasalah dan kita tidak bisa simpulkan apa-apa, jadi skip.
        ctrl_url = urljoin(
            target.origin + "/", f"cyberloka_{secrets.token_hex(4)}_/"
        )
        ctrl = client.get(ctrl_url, allow_redirects=False)
        if ctrl is not None and ctrl.status_code == 200:
            ctrl_listing, _ = _looks_like_listing(ctrl.text or "")
            if ctrl_listing:
                return findings  # everything looks like listing → unreliable

        for d in CANDIDATE_DIRS:
            url = urljoin(target.origin + "/", d)
            resp = client.get(url, allow_redirects=False)
            if resp is None or resp.status_code != 200:
                continue
            ok, anchor_count = _looks_like_listing(resp.text or "")
            if not ok:
                continue

            proof = ValidationProof(
                method="title+anchors+control",
                confirmed=True,
                steps=[
                    f"GET {url} → 200 OK.",
                    f"Title cocok pola 'Index of /' atau 'Directory listing for'.",
                    f"Body memuat {anchor_count} anchor `<a href=...>` (≥3).",
                    "Kontrol path random tidak menampilkan listing palsu.",
                ],
                samples=[f"anchors={anchor_count}"],
            )
            findings.append(
                Finding(
                    module="dirlist",
                    title=f"Directory listing aktif: {url}",
                    severity=Severity.MEDIUM,
                    description=(
                        "Server menampilkan daftar isi direktori. Attacker dapat menelusuri "
                        "file untuk mencari konfigurasi/backup."
                    ),
                    target=url,
                    urls=[url],
                    evidence=f"HTTP 200, anchors={anchor_count}, title=Index of …",
                    confidence="confirmed",
                    remediation=(
                        "Matikan autoindex / directory listing di web server "
                        "(`autoindex off` di Nginx, `Options -Indexes` di Apache)."
                    ),
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
