"""File upload misconfiguration probe (safe, non-RCE payload)."""
from __future__ import annotations

import io
import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state

UPLOAD_HINTS = re.compile(r"upload|avatar|photo|picture|attachment|berkas|lampiran|ktp|bukti", re.I)

# Marker unik tapi tidak eksekutif (HTML komentar)
MARKER = b"<!--cyberloka-upload-marker-->"

# (filename, content-type, payload, severity_if_accepted)
PAYLOADS = [
    ("cyberloka.html", "text/html", MARKER + b"<h1>marker</h1>", Severity.HIGH),
    ("cyberloka.svg", "image/svg+xml",
     b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg">' +
     MARKER + b"<text>m</text></svg>", Severity.HIGH),
    ("cyberloka.php.jpg", "image/jpeg", b"\xff\xd8\xff\xe0" + MARKER, Severity.HIGH),
    ("cyberloka.phtml", "application/octet-stream", MARKER + b"phtml", Severity.HIGH),
    ("..%2fcyberloka.txt", "text/plain", MARKER, Severity.MEDIUM),  # path traversal
]


def _upload_forms(config: ScanConfig) -> list[dict]:
    state = get_state(config)
    if not state:
        return []
    out = []
    for f in state.forms:
        if any(i.get("type") == "file" for i in f["inputs"]):
            out.append(f)
            continue
        if UPLOAD_HINTS.search((f.get("action") or "")):
            out.append(f)
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        forms = _upload_forms(config)
        for form in forms[:3]:
            file_field = next((i for i in form["inputs"] if i.get("type") == "file"), None)
            if not file_field:
                continue
            field_name = file_field["name"]
            other = {i["name"]: (i.get("value") or "x") for i in form["inputs"]
                     if i is not file_field and i.get("type") not in ("submit", "button")}
            for fname, ctype, body, sev in PAYLOADS:
                files = {field_name: (fname, io.BytesIO(body), ctype)}
                r = client.post(form["action"], data=other, files=files)
                if r is None:
                    continue
                if r.status_code >= 500:
                    continue
                rbody = (r.text or "")
                # Heuristik: server merespons dengan path/URL yang berisi nama file kita
                if r.status_code in (200, 201) and (
                    fname in rbody or fname.split(".")[0] in rbody.lower()
                ):
                    findings.append(Finding(
                        module="file_upload",
                        title=f"Upload diterima dengan filename mencurigakan: `{fname}`",
                        severity=sev,
                        description=("Server menerima file dengan ekstensi/nama yang "
                                     "umum dipakai bypass filter (double-ext, traversal, "
                                     "executable). Verifikasi manual apakah file dapat "
                                     "diakses & dieksekusi."),
                        target=form["action"],
                        evidence=truncate(f"status={r.status_code} body[0:200]={rbody[:200]}"),
                        cwe="CWE-434", confidence="tentative",
                        remediation=("Whitelist ekstensi & MIME (cek isi file, bukan hanya "
                                     "header), generate nama file random server-side, "
                                     "simpan di luar webroot atau di storage object, "
                                     "dan serve via endpoint yang set Content-Type aman."),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
                        ],
                    ))
                    break
    finally:
        client.close()
    return findings
