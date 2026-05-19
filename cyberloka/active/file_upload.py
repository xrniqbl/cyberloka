"""File-upload misconfig probe — strict-validation v0.10.1.

False-positive guards: setelah server merespons 200/201 dengan filename
kita di body, kami mencoba men-FETCH KEMBALI URL upload tersebut. Kalau
isinya benar memuat MARKER yang kita kirim → confirmed.
"""
from __future__ import annotations

import io
import re

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    ValidationProof,
    build_extra,
)
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state
from cyberloka.reporting.awam import get_awam

UPLOAD_HINTS = re.compile(
    r"upload|avatar|photo|picture|attachment|berkas|lampiran|ktp|bukti", re.I
)

MARKER = b"<!--cyberloka-upload-marker-->"
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
PATH_RE = re.compile(r"\"(/uploads?/[^\"']+)\"|'(/uploads?/[^'\"]+)'", re.I)

PAYLOADS = [
    ("cyberloka.html", "text/html", MARKER + b"<h1>marker</h1>", Severity.HIGH),
    ("cyberloka.svg", "image/svg+xml",
     b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg">' +
     MARKER + b"<text>m</text></svg>", Severity.HIGH),
    ("cyberloka.php.jpg", "image/jpeg", b"\xff\xd8\xff\xe0" + MARKER, Severity.HIGH),
    ("cyberloka.phtml", "application/octet-stream", MARKER + b"phtml", Severity.HIGH),
    ("..%2fcyberloka.txt", "text/plain", MARKER, Severity.MEDIUM),
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


def _extract_uploaded_url(rbody: str, fname: str, base: str) -> str | None:
    m = URL_RE.findall(rbody)
    for u in m:
        if fname.split(".")[0].lower() in u.lower():
            return u
    pm = PATH_RE.findall(rbody)
    for groups in pm:
        path = next((g for g in groups if g), None)
        if path and fname.split(".")[0].lower() in path.lower():
            from urllib.parse import urljoin
            return urljoin(base, path)
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    awam_summary, awam_steps = get_awam("file_upload")
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
                if r is None or r.status_code >= 500:
                    continue
                rbody = r.text or ""
                if r.status_code not in (200, 201):
                    continue
                if fname not in rbody and fname.split(".")[0] not in rbody.lower():
                    continue

                # Try to fetch back the uploaded file & check marker
                uploaded_url = _extract_uploaded_url(rbody, fname, target.origin + "/")
                marker_back = False
                fetched_url = uploaded_url
                if uploaded_url:
                    rback = client.get(uploaded_url)
                    if rback is not None and rback.status_code == 200:
                        marker_back = MARKER in (rback.content or b"")

                confidence = "confirmed" if marker_back else "tentative"
                proof = ValidationProof(
                    method="upload-then-fetchback" if marker_back else "upload-only",
                    confirmed=marker_back,
                    steps=[
                        f"Upload `{fname}` ke `{form['action']}`.",
                        f"Status response: {r.status_code}; body memuat nama file kita.",
                        (f"Fetch kembali `{uploaded_url}` → MARKER unik kami DITEMUKAN "
                         "→ file benar-benar tersimpan & bisa diakses publik."
                         if marker_back else
                         "Tidak bisa fetch kembali file (URL tidak ditemukan di response). "
                         "Confidence diturunkan ke 'tentative' — verifikasi manual."),
                    ],
                    samples=[
                        f"status={r.status_code}, body[:200]={rbody[:200]}",
                        f"uploaded_url={fetched_url or 'unknown'}",
                    ],
                )
                findings.append(Finding(
                    module="file_upload",
                    title=f"Upload diterima dengan filename mencurigakan: `{fname}`",
                    severity=sev if marker_back else Severity.MEDIUM,
                    description=("Server menerima file dengan ekstensi/nama yang umum "
                                 "dipakai bypass filter (double-ext, traversal, executable). "
                                 + (
                                    "Berhasil di-fetch kembali dari URL publik dengan marker "
                                    "unik kami → confirmed exposure."
                                    if marker_back else
                                    "Tidak dapat memverifikasi fetch-back; verifikasi manual "
                                    "apakah file dapat diakses & dieksekusi."
                                 )),
                    target=form["action"],
                    urls=[u for u in [form["action"], fetched_url] if u],
                    evidence=truncate(f"status={r.status_code} body[0:200]={rbody[:200]}"),
                    cwe="CWE-434",
                    confidence=confidence,
                    remediation=("Whitelist ekstensi & MIME (cek isi file, bukan hanya "
                                 "header), generate nama file random server-side, "
                                 "simpan di luar webroot atau di storage object, "
                                 "dan serve via endpoint yang set Content-Type aman."),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
                    ],
                    extra=build_extra(
                        proof=proof,
                        awam_steps=awam_steps,
                        awam_summary=awam_summary,
                    ),
                ))
                break
    finally:
        client.close()
    return findings
