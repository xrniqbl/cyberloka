"""Spring Boot Actuator exposure (env, heapdump, jolokia, mappings).

Auto-validation: probe /actuator/* dan validasi response JSON khas Spring
Boot (key `propertySources`, `mappings`, `_links`, `application`, dll).

Catatan verifikasi heapdump:
  Versi lama memakai signature `"\\x1f\\x8b"` (magic gzip, hanya 2 byte) dengan
  pengecekan substring `in body` — sehingga RESPON BINER/GZIP APA PUN yang kebetulan
  memuat dua byte itu di mana saja ter-flag sebagai "heapdump CRITICAL confirmed"
  (prediksi, bukan bukti). Kini heapdump hanya dikonfirmasi bila:
    - body memuat signature HPROF teks ("JAVA PROFILE"/"HPROF") di awal, ATAU
    - raw body DIMULAI dengan magic gzip/zip DAN content-type biner DAN ukuran
      berarti (>1KB) — pola yang tak bisa muncul dari halaman HTML/JSON biasa.
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

HEAPDUMP_PATHS = {"/actuator/heapdump", "/heapdump"}
HPROF_TEXT_SIG = ("JAVA PROFILE", "HPROF")
GZIP_MAGIC = b"\x1f\x8b"
ZIP_MAGIC = b"PK\x03\x04"

# (path, validator_substring, severity_override). Untuk path heapdump signature
# di-handle khusus oleh _is_heapdump (lihat docstring) — list di sini hanya
# dipakai modul non-biner.
ACTUATOR_PATHS: list[tuple[str, list[str], Severity]] = [
    ("/actuator",          ['"_links"', '"actuator"', '"health"'], Severity.MEDIUM),
    ("/actuator/env",      ['"propertySources"', '"systemEnvironment"'], Severity.CRITICAL),
    ("/env",               ['"propertySources"', '"systemEnvironment"'], Severity.CRITICAL),
    ("/actuator/heapdump", list(HPROF_TEXT_SIG), Severity.CRITICAL),
    ("/heapdump",          list(HPROF_TEXT_SIG), Severity.CRITICAL),
    ("/actuator/jolokia",  ['"agent"', '"protocol"', "jolokia"], Severity.CRITICAL),
    ("/jolokia",           ['"agent"', '"protocol"', "jolokia"], Severity.CRITICAL),
    ("/actuator/mappings", ['"contexts"', '"dispatcherServlets"'], Severity.HIGH),
    ("/actuator/beans",    ['"contexts"', '"beans"'], Severity.HIGH),
    ("/actuator/threaddump", ['"threads"', '"threadName"'], Severity.HIGH),
    ("/actuator/configprops", ['"contexts"', '"contextId"'], Severity.HIGH),
]


def _is_heapdump(r) -> bool:
    """Bukti heapdump nyata — bukan sekadar 2 byte gzip di tengah teks."""
    raw = r.content or b""
    if not raw:
        return False
    # HPROF tak-terkompresi: signature teks sangat spesifik di awal file.
    head_text = raw[:64].decode("latin-1", "ignore")
    if any(sig in head_text for sig in HPROF_TEXT_SIG):
        return True
    # Heapdump terkompresi: HARUS dimulai magic gzip/zip + content-type biner + besar.
    ctype = (r.headers.get("Content-Type") or "").lower()
    binary_ct = (
        ctype == ""
        or "application/octet-stream" in ctype
        or "application/x-" in ctype
        or "force-download" in ctype
    )
    if (raw.startswith(GZIP_MAGIC) or raw.startswith(ZIP_MAGIC)) and binary_ct and len(raw) > 1024:
        return True
    return False


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    seen = set()
    try:
        for path, signatures, sev in ACTUATOR_PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            if path in HEAPDUMP_PATHS:
                if not _is_heapdump(r):
                    continue
                evidence = f"GET {url} -> 200; heapdump terkonfirmasi (HPROF/biner ter-anchor)"
            else:
                body_head = (r.text or "")[:4096]
                if not any(sig in body_head for sig in signatures):
                    continue
                evidence = f"GET {url} -> 200; signature match."
            key = path.split("/")[-1]
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                module="spring_actuator_rce",
                title=f"Spring Boot Actuator ter-expose: {path}",
                severity=sev,
                description=(
                    "Endpoint actuator Spring Boot dapat diakses tanpa autentikasi. "
                    f"Path `{path}` mengandalikan ekstraksi kredensial / heapdump / "
                    "Jolokia chain ke RCE."
                ),
                target=url,
                urls=[url],
                evidence=evidence,
                cwe="CWE-200",
                confidence="confirmed",
                remediation=(
                    "Aktifkan `spring.boot.admin.client.enabled=false` untuk "
                    "actuator publik, dan amankan dengan basic-auth: "
                    "`management.endpoints.web.exposure.include=health,info`. "
                    "Bind actuator ke localhost: "
                    "`management.server.port=-1` atau via reverse-proxy filter."
                ),
                references=[
                    "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
                    "https://www.veracode.com/blog/research/exploiting-spring-boot-actuators",
                ],
            ))
    finally:
        client.close()
    return findings
