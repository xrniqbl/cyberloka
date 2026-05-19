"""Joomla! fingerprint & exposure scanner.

Validasi sebelum report (minimal salah satu marker harus match):
    1. meta `<meta name="generator" content="Joomla!">`
    2. body root memuat `option=com_users` atau `Joomla!`
    3. `/administrator/` 200 dengan title `Joomla!`
    4. `/language/en-GB/en-GB.xml` valid Joomla XML

Probe tambahan setelah confirmed Joomla:
    * `/administrator/`             - panel publik (severity HIGH).
    * `/htaccess.txt`               - default htaccess yang lupa di-rename.
    * `/configuration.php-dist`     - konfigurasi default.
    * `/installation/`              - direktori install yang lupa di-hapus
                                      (CRITICAL).
    * `/language/en-GB/en-GB.xml`   - versi Joomla.
    * `/api/index.php/v1/users`     - Web Services API (Joomla 4+).
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

GEN_RE = re.compile(
    r'<meta\s+name=[\'"]generator[\'"]\s+content=[\'"]Joomla!?\s*-?\s*([\d.]*)',
    re.I,
)
LANG_VER_RE = re.compile(r"<version>\s*([\d.]+)\s*</version>", re.I)


def _is_joomla(client: HttpClient, target: Target) -> tuple[bool, str, str]:
    base = target.origin + "/"
    r = client.get(target.base_url, allow_redirects=True)
    if r is None:
        return False, "", ""
    body = r.text or ""
    m = GEN_RE.search(body)
    if m:
        return True, (m.group(1) or "").strip(), "meta generator"
    if "option=com_users" in body or "Joomla!" in body:
        # konfirmasi via language file
        lr = client.get(urljoin(base, "language/en-GB/en-GB.xml"),
                        allow_redirects=False)
        if lr and lr.status_code == 200 and "<extension" in (lr.text or ""):
            mv = LANG_VER_RE.search(lr.text or "")
            return True, (mv.group(1) if mv else ""), "language xml"
    # Direct admin probe
    ar = client.get(urljoin(base, "administrator/"), allow_redirects=True)
    if ar and ar.status_code == 200 and "Joomla" in (ar.text or ""):
        return True, "", "administrator/"
    return False, "", ""


def _probe(client: HttpClient, target: Target,
           path: str, marker: str | None,
           title: str, sev: Severity, desc: str,
           remediation: str, cwe: str = "CWE-538") -> Finding | None:
    url = urljoin(target.origin + "/", path)
    r = client.get(url, allow_redirects=False)
    if r is None or r.status_code >= 400:
        return None
    if marker and marker not in (r.text or ""):
        return None
    return Finding(
        module="joomla_scan",
        title=title,
        severity=sev,
        description=desc,
        target=url,
        evidence=truncate(f"HTTP {r.status_code}, len={len(r.content or b'')}",
                          120),
        cwe=cwe,
        confidence="confirmed",
        remediation=remediation,
        extra={"reverify": {"status": (200, 401, 403)} if not marker
               else {"marker": marker, "in_body": True}},
    )


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        is_j, version, ev = _is_joomla(client, target)
        if not is_j:
            return findings

        findings.append(Finding(
            module="joomla_scan",
            title=f"Joomla! terdeteksi" + (f" v{version}" if version else ""),
            severity=Severity.LOW if not version else Severity.MEDIUM,
            description=(
                "Site memakai Joomla!. Probe tambahan akan menyusul: "
                "/administrator panel, /installation directory, default "
                "htaccess, language file, REST API."
            ),
            target=target.base_url,
            evidence=f"fingerprint: {ev}; version={version or 'unknown'}",
            cwe="CWE-200",
            confidence="confirmed",
            remediation=(
                "Selalu update Joomla! ke versi minor terbaru. Audit "
                "extension yang dipakai dan hapus yang tidak aktif."
            ),
            references=["https://www.joomla.org/announcements/release-news/"],
        ))

        for f in (
            _probe(client, target, "administrator/", "Joomla",
                   "Panel admin Joomla terbuka publik", Severity.MEDIUM,
                   "Panel `/administrator/` dapat diakses dari internet — "
                   "rentan brute-force kalau tidak ada IP allowlist + 2FA.",
                   "IP allowlist + basic-auth tambahan + 2FA wajib untuk "
                   "akses panel admin."),
            _probe(client, target, "installation/index.php", None,
                   "Direktori installation/ Joomla belum dihapus",
                   Severity.CRITICAL,
                   "`/installation/` masih dapat diakses — bisa dipakai "
                   "untuk re-install Joomla dan mengambil alih site.",
                   "Hapus folder `/installation/` setelah instalasi selesai. "
                   "Kalau perlu re-install, lakukan dari hosting panel "
                   "(bukan dari URL publik)."),
            _probe(client, target, "htaccess.txt",
                   "RewriteEngine",
                   "File htaccess.txt default Joomla terbuka",
                   Severity.LOW,
                   "File htaccess.txt default Joomla terbuka — biasanya "
                   "berisi rule yang harus di-rename ke `.htaccess`.",
                   "Rename `htaccess.txt` -> `.htaccess` (Apache) supaya "
                   "rewrite + security rule aktif."),
            _probe(client, target, "configuration.php-dist", "JConfig",
                   "configuration.php-dist (template config) terbuka",
                   Severity.MEDIUM,
                   "Template konfigurasi Joomla terbuka publik. Bukan "
                   "bocoran kredensial, tapi mengonfirmasi versi & "
                   "struktur.",
                   "Hapus `configuration.php-dist` dari webroot."),
            _probe(client, target, "api/index.php/v1/config/application",
                   "errors", "Joomla 4 Web Services API responding",
                   Severity.LOW,
                   "Web Services API Joomla 4+ aktif. Pastikan setiap "
                   "endpoint memerlukan token autentikasi.",
                   "Audit semua endpoint /api/* dan pastikan token-based "
                   "auth aktif. Tutup endpoint yang tidak dipakai."),
        ):
            if f:
                findings.append(f)
    finally:
        client.close()
    return findings
