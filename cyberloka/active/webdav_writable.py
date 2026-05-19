"""WebDAV PUT/PROPFIND writable detection.

Auto-validation: roundtrip OPTIONS -> PROPFIND -> PUT -> GET. Bila
GET kembali memuat byte yang persis sama dengan PUT body -> WebDAV
write terbuka.
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

POC_PATH = "cyblok-webdav-poc.txt"
POC_BODY = b"CYBLOK_WEBDAV_PUT_VALIDATION"
WEBDAV_METHODS = ("PROPFIND", "MKCOL", "PUT", "DELETE", "MOVE", "COPY", "LOCK")


def _allowed_methods(headers: dict) -> set[str]:
    allow = (headers.get("Allow") or "") + " " + (headers.get("Public") or "")
    return {m.strip().upper() for m in allow.split(",") if m.strip()}


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # Cek OPTIONS dulu — apakah ada method WebDAV
        opt = client.options(target.origin + "/")
        if opt is None:
            return findings
        allowed = _allowed_methods(dict(opt.headers))
        webdav_seen = allowed & set(WEBDAV_METHODS)
        if not webdav_seen:
            return findings

        # PROPFIND validasi DAV aktif
        pf = client.request("PROPFIND", target.origin + "/",
                            headers={"Depth": "0",
                                     "Content-Type": "application/xml"},
                            data=b"")
        if pf is None or pf.status_code not in (207, 200):
            # Tidak fatal — tetap probe PUT
            pass

        # Pastikan PUT ada di Allow
        if "PUT" not in allowed:
            findings.append(_finding(
                target.origin + "/", Severity.MEDIUM, "firm",
                f"OPTIONS Allow={','.join(sorted(webdav_seen))} (WebDAV aktif tapi PUT tidak terlihat)",
                f"Method WebDAV terdeteksi: {', '.join(sorted(webdav_seen))}",
                webdav_seen,
            ))
            return findings

        url = urljoin(target.origin + "/", POC_PATH)
        # PUT
        rp = client.request("PUT", url, data=POC_BODY,
                            headers={"Content-Type": "text/plain"})
        if rp is None or rp.status_code not in (200, 201, 204):
            findings.append(_finding(
                target.origin + "/", Severity.MEDIUM, "firm",
                f"PUT {url} -> {rp.status_code if rp else 'no-resp'}; method ada di Allow",
                f"Method WebDAV terdeteksi: {', '.join(sorted(webdav_seen))} "
                f"(PUT tidak diterima saat ini, tapi method publik)",
                webdav_seen,
            ))
            return findings

        # GET kembali
        rg = client.get(url)
        if rg is None or rg.status_code != 200 or POC_BODY not in (rg.content or b""):
            findings.append(_finding(
                url, Severity.HIGH, "firm",
                f"PUT {url} -> {rp.status_code}; GET tidak balas isi sama",
                f"PUT diterima ({rp.status_code}) tapi tidak persis ter-roundtrip",
                webdav_seen,
            ))
            return findings

        findings.append(_finding(
            url, Severity.CRITICAL, "confirmed",
            f"PUT {url} -> {rp.status_code}; GET balas {len(rg.content)} bytes identik",
            "Full WebDAV write tervalidasi (roundtrip).",
            webdav_seen,
        ))
        # Cleanup
        client.request("DELETE", url)
    finally:
        client.close()
    return findings


def _finding(url: str, sev: Severity, conf: str, evidence: str,
             note: str, methods: set) -> Finding:
    return Finding(
        module="webdav_writable",
        title="WebDAV / PUT method terbuka",
        severity=sev,
        description=(
            "Server merespons method WebDAV (PROPFIND/PUT/MOVE) untuk "
            f"client anonim. {note}. Bila full-write tersedia, attacker "
            "dapat upload file `.aspx`/`.jsp`/`.php` -> webshell + RCE."
        ),
        target=url,
        urls=[url],
        evidence=evidence + f"; methods={sorted(methods)}",
        cwe="CWE-650",
        confidence=conf,
        remediation=(
            "Disable modul WebDAV / `dav` di Nginx, Apache, IIS bila tidak "
            "dipakai. Bila perlu (mis. shared editing), pasang basic-auth "
            "+ filter ekstensi: tolak PUT untuk `*.php|*.jsp|*.aspx|*.cgi`. "
            "Pasang IP allowlist."
        ),
        references=[
            "https://datatracker.ietf.org/doc/html/rfc4918",
        ],
    )
