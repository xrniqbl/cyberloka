"""IIS short-name (8.3) disclosure detection.

Auto-validation: bandingkan respons untuk path tilde-wildcard pada IIS.
- valid 8.3 prefix -> 404 Not Found
- invalid prefix    -> 400 Bad Request
Bila kedua status berbeda dengan baseline biasa = vulnerable.
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# Probes
PROBES = [
    "/*~1*/.aspx",
    "/a*~1*/.aspx",
    "/*~1*/a.aspx",
]
INVALID_PROBE = "/cyblok_xyz_does_not_exist*~1*/.aspx"


def _is_iis(headers: dict) -> bool:
    server = (headers.get("Server") or "").lower()
    powered = (headers.get("X-Powered-By") or "").lower()
    return "iis" in server or "asp.net" in powered or "x-aspnet-version" in [
        k.lower() for k in headers.keys()
    ]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # Konfirmasi IIS
        head = client.get(target.origin)
        if head is None or not _is_iis(dict(head.headers)):
            return findings

        # Probe baseline (file dummy umum) untuk benchmark 404
        baseline = client.get(urljoin(target.origin + "/", "definitely_not_real_xyzz.aspx"))
        baseline_status = baseline.status_code if baseline else 0

        # Probe invalid wildcard => harus 404 di server normal
        invalid_url = urljoin(target.origin + "/", INVALID_PROBE.lstrip("/"))
        ri = client.get(invalid_url, allow_redirects=False)
        if ri is None:
            return findings

        # Probe valid wildcard
        for probe in PROBES:
            url = urljoin(target.origin + "/", probe.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None:
                continue
            # Klasik: tilde enumeration aktif kalau ada perbedaan 404 vs 400
            if r.status_code in (400, 404) and ri.status_code in (400, 404) \
                    and r.status_code != ri.status_code:
                findings.append(Finding(
                    module="iis_shortname",
                    title="IIS Short-Name (8.3) disclosure aktif",
                    severity=Severity.HIGH,
                    description=(
                        "IIS membedakan response untuk path tilde-wildcard "
                        "yang valid vs invalid (probe valid={} vs invalid={}). "
                        "Pola ini dipakai shortscan / IIS-ShortName-Scanner "
                        "untuk meng-enumerasi nama file 8.3 (mis. backup~1.zip)."
                    ).format(r.status_code, ri.status_code),
                    target=url,
                    urls=[url, invalid_url],
                    evidence=(
                        f"baseline_status={baseline_status}; "
                        f"valid_probe={url} -> {r.status_code}; "
                        f"invalid_probe={invalid_url} -> {ri.status_code}"
                    ),
                    cwe="CWE-200",
                    confidence="confirmed",
                    remediation=(
                        "Disable 8.3 short name di Windows: "
                        "`fsutil 8dot3name set 1` (registry) lalu reboot. "
                        "Atau di IIS: `Request Filtering -> URL Sequences` "
                        "deny `~`. Pakai web.config untuk filter path bertanda "
                        "`~`. Pastikan semua disk yang melayani konten "
                        "tidak punya entri 8.3 (jalankan `fsutil 8dot3name "
                        "strip`)."
                    ),
                    references=[
                        "https://soroush.secproject.com/blog/2010/07/iis-short-file-name-disclosure-vulnerability/",
                    ],
                ))
                break
    finally:
        client.close()
    return findings
