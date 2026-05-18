"""HTTP method enumeration / dangerous methods.

Akurasi yang ditambahkan:

- TRACE: dianggap aktif **hanya** kalau body memantulkan header request kustom
  yang kita kirim (`X-Cyberloka: <nonce>`).
- PUT/DELETE: setelah server mengiklankan via OPTIONS, kita lakukan probe
  TANPA mengubah file: kirim PUT ke path acak yg tidak ada dan periksa kalau
  status menjadi 201/204 (created/written). Bila ya → CRITICAL. Bila 401/403
  → server hanya mengizinkan dengan auth (informasional).
- TRACK (IIS): probe metode TRACK juga.
"""
from __future__ import annotations

import secrets
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

DANGEROUS = {"PUT", "DELETE", "TRACE", "TRACK", "CONNECT", "PATCH"}


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        url = target.base_url
        resp = client.options(url)
        allow = ""
        if resp is not None:
            allow = resp.headers.get("Allow", "") or resp.headers.get(
                "Access-Control-Allow-Methods", ""
            )
        allowed = {m.strip().upper() for m in allow.split(",") if m.strip()}

        # --- TRACE confirmation ---------------------------------------------
        nonce = secrets.token_hex(6)
        trace_resp = client.request(
            "TRACE",
            url,
            allow_redirects=False,
            headers={"X-Cyberloka": nonce},
        )
        trace_active = (
            trace_resp is not None
            and trace_resp.status_code == 200
            and nonce in (trace_resp.text or "")
        )
        if trace_active:
            findings.append(
                Finding(
                    module="methods",
                    title="HTTP TRACE aktif (Cross-Site Tracing)",
                    severity=Severity.MEDIUM,
                    description=(
                        "TRACE me-mantulkan header request ke client; bila dipakai bersama "
                        "vulnerability lain (mis. flash/HTML injection), dapat membocorkan "
                        "cookie HttpOnly. Verifikasi dengan custom header `X-Cyberloka` "
                        "yang muncul di body."
                    ),
                    target=url,
                    evidence=f"X-Cyberloka nonce {nonce} ditemukan di body TRACE response.",
                    cwe="CWE-489",
                    confidence="confirmed",
                    remediation=(
                        "Nonaktifkan TRACE/TRACK di web server (`TraceEnable Off` di Apache, "
                        "blok di Nginx via `if ($request_method = TRACE)`, drop di reverse "
                        "proxy)."
                    ),
                )
            )

        # --- PUT write probe -------------------------------------------------
        if "PUT" in allowed:
            probe = urljoin(target.origin + "/", f"cyberloka-write-{nonce}.txt")
            put_resp = client.request(
                "PUT",
                probe,
                data=b"cyberloka",
                allow_redirects=False,
            )
            if put_resp is not None and put_resp.status_code in (200, 201, 204):
                # Try to read it back
                read = client.get(probe, allow_redirects=False)
                wrote = read is not None and read.status_code == 200 and "cyberloka" in (read.text or "")
                # Best-effort cleanup
                client.request("DELETE", probe, allow_redirects=False)
                findings.append(
                    Finding(
                        module="methods",
                        title="HTTP PUT diizinkan untuk MENULIS file pada server",
                        severity=Severity.CRITICAL,
                        description=(
                            "Server menerima PUT ke path acak dan mengembalikan status "
                            "create/no-content. Bila body terbaca kembali, attacker dapat "
                            "mengunggah file (termasuk shell PHP/JSP) → RCE."
                        ),
                        target=probe,
                        evidence=f"PUT status: {put_resp.status_code}; readable={wrote}",
                        cwe="CWE-650",
                        confidence="confirmed" if wrote else "firm",
                        remediation=(
                            "Nonaktifkan metode PUT di web server. Bila diperlukan WebDAV, "
                            "wajib di-protect dengan auth & batasan path."
                        ),
                    )
                )
            elif put_resp is not None and put_resp.status_code in (401, 403):
                findings.append(
                    Finding(
                        module="methods",
                        title="HTTP PUT diiklankan tapi terlindung (401/403)",
                        severity=Severity.INFO,
                        description="PUT ada tapi memerlukan otentikasi.",
                        target=probe,
                        evidence=f"PUT status: {put_resp.status_code}",
                        confidence="firm",
                    )
                )

        # --- DELETE probe ----------------------------------------------------
        if "DELETE" in allowed:
            probe = urljoin(target.origin + "/", f"cyberloka-del-{nonce}.txt")
            del_resp = client.request("DELETE", probe, allow_redirects=False)
            if del_resp is not None and del_resp.status_code in (200, 204):
                findings.append(
                    Finding(
                        module="methods",
                        title="HTTP DELETE diizinkan tanpa otentikasi",
                        severity=Severity.HIGH,
                        description=(
                            "DELETE ke path acak tidak ditolak. Attacker bisa menghapus konten."
                        ),
                        target=probe,
                        evidence=f"DELETE status: {del_resp.status_code}",
                        cwe="CWE-650",
                        confidence="firm",
                        remediation="Nonaktifkan DELETE di web server publik.",
                    )
                )

        # --- Catch-all: methods advertised but not actively tested ----------
        risky = allowed & DANGEROUS - {"TRACE", "PUT", "DELETE"}
        if risky:
            findings.append(
                Finding(
                    module="methods",
                    title=f"Metode HTTP berisiko diiklankan: {', '.join(sorted(risky))}",
                    severity=Severity.LOW,
                    description=(
                        "Server mengiklankan metode yang jarang dibutuhkan publik. "
                        "Nilai sensitivitasnya tergantung apakah endpoint write benar-benar "
                        "ter-protect oleh auth — perlu uji manual."
                    ),
                    target=url,
                    evidence=f"Allow: {allow}",
                    cwe="CWE-489",
                    confidence="firm",
                    remediation=(
                        "Whitelist metode di reverse-proxy (`GET, HEAD, POST` saja untuk "
                        "endpoint publik). Pastikan endpoint write hanya dapat diakses "
                        "dengan otentikasi yang benar."
                    ),
                )
            )
    finally:
        client.close()
    return findings
