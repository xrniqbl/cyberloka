"""Probe known framework default / debug paths — strict-validation v0.10.6.

PERUBAHAN PENTING (perbaikan false-positive):
  Versi lama menandai path (mis. `/_ignition/execute-solution`, `/.env`)
  sebagai CRITICAL hanya dari `HTTP 200` + marker kosong/lemah (`""` atau `"="`).
  Server SPA/catch-all membalas SATU halaman HTML yang sama (mis. 1569 byte)
  untuk URL apa pun, sehingga endpoint yang sebenarnya TIDAK ADA dilaporkan
  sebagai celah CRITICAL.

  Sekarang setiap path WAJIB:
    1. Bukan soft-404 / SPA shell (``is_soft_200``).
    2. Bukan halaman catch-all (sama dengan kontrol path acak).
    3. Cocok marker konten SPESIFIK (tidak ada lagi marker kosong).
  Plus penanganan khusus berbukti untuk:
    * ``/.env``  → wajib berbentuk KEY=VALUE & bukan HTML.
    * ``/_ignition/execute-solution`` → probe POST aman yang membuktikan
      endpoint benar-benar handler Laravel Ignition (CVE-2021-3129), bukan
      halaman catch-all. (Rantai RCE penuh TIDAK dijalankan — destruktif.)
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import (
    Finding,
    HttpClient,
    Severity,
    Target,
    catch_all_control,
    is_catch_all_response,
    is_soft_200,
    looks_like_html_shell,
)
from cyberloka.core.config import ScanConfig

# (path, label, severity, marker) — marker WAJIB non-kosong & spesifik.
PATHS = [
    ("/actuator/env", "Spring actuator env", Severity.HIGH, "activeProfiles"),
    ("/actuator/health", "Spring actuator", Severity.LOW, '"status"'),
    ("/console", "Werkzeug debug console", Severity.CRITICAL, "Werkzeug"),
    ("/server-status", "Apache server-status", Severity.HIGH, "Apache Server Status"),
    ("/server-info", "Apache server-info", Severity.MEDIUM, "Apache Server Information"),
    ("/wp-login.php", "WordPress login", Severity.LOW, "wp-submit"),
    ("/manager/html", "Tomcat Manager", Severity.HIGH, "Apache Tomcat"),
    ("/jolokia/", "Jolokia JMX bridge", Severity.HIGH, '"agent"'),
    ("/phpmyadmin/", "phpMyAdmin", Severity.MEDIUM, "pma_password"),
    ("/swagger-ui.html", "Swagger UI v2", Severity.MEDIUM, "swagger-ui"),
    ("/swagger-ui/", "Swagger UI v3", Severity.MEDIUM, "swagger-ui"),
]

# Tanda-tangan respons khas Laravel Ignition saat menerima solution invalid.
_IGNITION_SIG = re.compile(
    r"(ignition|spatie\\?/?laravel-?ignition|facade\\ignition|"
    r"does not exist|class .* not found|illuminate\\|"
    r"makeviewvariableoptional|executesolutioncontroller|"
    r'"solution"|symfony\\component)',
    re.I,
)
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?[A-Z][A-Z0-9_]*\s*=", re.M)
_HPROF_SIG = (b"JAVA PROFILE", b"\x1f\x8b\x08")  # HPROF teks / gzip


def _is_htmlish(resp) -> bool:
    ct = (resp.headers.get("Content-Type") or "").lower()
    return "text/html" in ct or looks_like_html_shell(resp.text or "")


def _check_env(client: HttpClient, base: str, control_body: str | None):
    """`.env` nyata: KEY=VALUE & bukan HTML (bukan beranda yang memuat '=')."""
    url = urljoin(base, ".env")
    r = client.get(url)
    if r is None or r.status_code >= 400 or not r.content:
        return None
    if is_soft_200(r) or is_catch_all_response(r.text or "", control_body):
        return None
    body = r.text or ""
    if _is_htmlish(r) or len(_ENV_LINE.findall(body)) < 2:
        return None
    return Finding(
        module="framework_default",
        title="Env file (.env) ter-ekspos dengan isi kredensial",
        severity=Severity.CRITICAL,
        description=(
            "File `.env` dapat diakses publik dan KONTENNYA berbentuk KEY=VALUE "
            "(bukan halaman HTML catch-all). Berisiko membocorkan APP_KEY, "
            "kredensial DB, dan secret lain."
        ),
        target=url,
        urls=[url],
        evidence=f"HTTP {r.status_code}, {len(_ENV_LINE.findall(body))} baris KEY=VALUE, non-HTML",
        cwe="CWE-538",
        confidence="confirmed",
        remediation=(
            "Pindahkan `.env` keluar dari web root & blokir di web server "
            "(`location ~ /\\.env { deny all; }`). Rotasi semua secret yang bocor."
        ),
    )


def _check_ignition(client: HttpClient, base: str, control_body: str | None):
    """Laravel Ignition CVE-2021-3129: buktikan endpoint = handler Ignition.

    Probe AMAN & non-destruktif: POST solution yang tidak ada → Ignition asli
    membalas error spesifik (bukan halaman catch-all). Rantai RCE (log poison /
    phar) TIDAK dijalankan karena destruktif.
    """
    url = urljoin(base, "_ignition/execute-solution")
    payload = {"solution": "Cyberloka\\Nonexistent\\Solution", "parameters": {}}
    r = client.post(url, json=payload, headers={"Accept": "application/json"},
                    allow_redirects=False)
    if r is None:
        return None
    body = r.text or ""
    # Catch-all / SPA shell / not-found → BUKAN Ignition nyata.
    if is_soft_200(r) or is_catch_all_response(body, control_body):
        return None
    # HTML murni tanpa sinyal Ignition → bukan handler Ignition.
    if not _IGNITION_SIG.search(body):
        return None
    return Finding(
        module="framework_default",
        title="Laravel Ignition execute-solution ter-ekspos (CVE-2021-3129)",
        severity=Severity.CRITICAL,
        description=(
            "Endpoint `/_ignition/execute-solution` merespons sebagai handler "
            "Laravel Ignition (terbukti via POST: server membalas error khas "
            "Ignition, bukan halaman catch-all). Bila Ignition <= 2.5.1 dan "
            "APP_DEBUG=true, endpoint ini memungkinkan Remote Code Execution "
            "(CVE-2021-3129). Rantai RCE TIDAK dijalankan oleh scanner."
        ),
        target=url,
        urls=[url],
        evidence=(
            f"POST {url} -> HTTP {r.status_code}; respons memuat tanda-tangan "
            f"Ignition (bukan catch-all/HTML generik)"
        ),
        cwe="CWE-502",
        confidence="firm",
        remediation=(
            "Update `facade/ignition` atau `spatie/laravel-ignition` ke versi "
            "terbaru. Set `APP_DEBUG=false` di produksi. Hapus paket Ignition "
            "dari dependency produksi bila tidak diperlukan."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-3129"],
    )


def _check_heapdump(client: HttpClient, base: str, control_body: str | None):
    """`/actuator/heapdump`: wajib biner HPROF/gzip ter-anchor di AWAL."""
    url = urljoin(base, "actuator/heapdump")
    r = client.get(url)
    if r is None or r.status_code >= 400 or not r.content:
        return None
    raw = r.content or b""
    if not any(raw[:16].startswith(s) or s in raw[:32] for s in _HPROF_SIG):
        return None
    return Finding(
        module="framework_default",
        title="Spring actuator heapdump ter-ekspos (memory dump)",
        severity=Severity.CRITICAL,
        description=(
            "Endpoint `/actuator/heapdump` mengembalikan heap dump biner "
            "(signature HPROF/gzip ter-verifikasi). Memuat kredensial, token, "
            "dan data sensitif dari memori JVM."
        ),
        target=url,
        urls=[url],
        evidence=f"HTTP {r.status_code}, signature heapdump biner ter-anchor",
        cwe="CWE-200",
        confidence="confirmed",
        remediation=(
            "Batasi `management.endpoints.web.exposure.include` hanya ke "
            "`health`. Lindungi /actuator dengan auth + IP allowlist."
        ),
    )


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    base = target.origin + "/"
    try:
        control_body = catch_all_control(client, base)

        # Path khusus dengan validasi konten/eksploitasi berbukti.
        for special in (_check_env, _check_ignition, _check_heapdump):
            try:
                f = special(client, base, control_body)
            except Exception:
                f = None
            if f:
                findings.append(f)

        # Path generik: wajib marker spesifik + bukan soft-404/catch-all.
        for path, label, sev, marker in PATHS:
            url = urljoin(base, path.lstrip("/"))
            r = client.get(url)
            if r is None or r.status_code >= 400 or not r.content:
                continue
            if is_soft_200(r) or is_catch_all_response(r.text or "", control_body):
                continue
            body = r.text or ""
            if marker.lower() not in body.lower():
                continue
            findings.append(Finding(
                module="framework_default",
                title=f"Endpoint default/admin terbuka: {label} ({path})",
                severity=sev,
                description=(
                    "Path framework/admin standar dapat diakses publik dan "
                    "cocok marker konten spesifik (bukan halaman catch-all). "
                    "Verifikasi apakah perlu autentikasi atau dimatikan di produksi."
                ),
                target=url,
                urls=[url],
                evidence=f"HTTP {r.status_code}, marker spesifik '{marker}' cocok",
                cwe="CWE-489",
                confidence="firm",
                remediation=(
                    "Matikan endpoint debug/management di produksi, atau "
                    "lindungi dengan basic auth + IP allowlist."
                ),
            ))
    finally:
        client.close()
    return findings
