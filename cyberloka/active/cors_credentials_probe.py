"""CORS credential probe — preflight POST/PUT/DELETE + Allow-Credentials check.

Modul ``cors`` & ``cors_advanced`` umumnya cek GET request dengan Origin
attacker. Tapi kombinasi paling berbahaya adalah:

  POST/PUT/DELETE lintas-origin + Allow-Credentials: true + Allow-Origin
  yang reflect Origin attacker

artinya halaman attacker dapat memanggil API yang **mengubah state** sambil
membawa cookie sesi korban. Ini pintu CSRF-bypass + data exfiltration.

Alur probe:
1. Kirim CORS preflight (OPTIONS) ke endpoint state-changing yang umum
   (path ditebak dari ``CANDIDATE_PATHS`` + path yang ditemukan crawler).
2. Header preflight:
     Origin: https://evil.example.com
     Access-Control-Request-Method: POST/PUT/DELETE/PATCH
     Access-Control-Request-Headers: x-csrf-token, content-type
3. Cek response header:
     Access-Control-Allow-Origin
     Access-Control-Allow-Methods
     Access-Control-Allow-Credentials
     Access-Control-Allow-Headers

Severity:
- Reflect attacker origin + Allow-Credentials true + method state-changing
  diizinkan -> HIGH (CSRF + read).
- Wildcard Allow-Origin + Allow-Credentials -> CRITICAL (sebenarnya browser
  reject kombinasi ini, tapi tetap sinyal config salah).
- Reflect Origin + Allow-Credentials false -> MEDIUM (data leak via fetch
  no-credentials).
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

EVIL_ORIGIN = "https://evil.example.com"

CANDIDATE_PATHS = [
    "/api/account", "/api/profile", "/api/me",
    "/api/order", "/api/orders", "/api/cart", "/api/checkout",
    "/api/transfer", "/api/withdraw", "/api/topup",
    "/api/settings", "/api/preferences",
    "/api/password", "/api/email", "/api/2fa",
    "/api/v1/account", "/api/v1/order", "/api/v1/transfer",
]

STATE_CHANGING_METHODS = ["POST", "PUT", "DELETE", "PATCH"]


def _probe_preflight(client: HttpClient, url: str, method: str) -> dict | None:
    """Send OPTIONS preflight and return ACAO/ACAC/ACAM/ACAH."""
    headers = {
        "Origin": EVIL_ORIGIN,
        "Access-Control-Request-Method": method,
        "Access-Control-Request-Headers": "x-csrf-token, content-type, authorization",
    }
    r = client.request("OPTIONS", url, headers=headers, allow_redirects=False)
    if r is None:
        return None
    if r.status_code in (404, 410):
        return None
    h = {k.lower(): v for k, v in r.headers.items()}
    return {
        "status": r.status_code,
        "acao": h.get("access-control-allow-origin", ""),
        "acac": (h.get("access-control-allow-credentials") or "").lower(),
        "acam": h.get("access-control-allow-methods", ""),
        "acah": h.get("access-control-allow-headers", ""),
    }


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if not config.authorized:
        return findings
    client = HttpClient(config)
    seen: set[str] = set()
    try:
        for path in CANDIDATE_PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            if url in seen:
                continue
            seen.add(url)

            for method in STATE_CHANGING_METHODS:
                pf = _probe_preflight(client, url, method)
                if pf is None:
                    continue
                acao = pf["acao"]
                acac = pf["acac"] == "true"
                acam = pf["acam"].upper()

                # Server tidak balas CORS sama sekali -> aman atau bukan endpoint CORS
                if not acao:
                    continue

                method_allowed = method in acam or "*" in acam
                if not method_allowed:
                    continue

                # Reflect origin attacker?
                reflect_evil = acao == EVIL_ORIGIN
                wildcard_with_creds = acao == "*" and acac

                if wildcard_with_creds:
                    findings.append(
                        Finding(
                            module="cors_credentials_probe",
                            title=f"CORS: wildcard `*` + Allow-Credentials di {path}",
                            severity=Severity.CRITICAL,
                            description=(
                                "Kombinasi `Access-Control-Allow-Origin: *` + "
                                "`Access-Control-Allow-Credentials: true` LARANGAN per spec "
                                "CORS. Browser modern akan refuse kombinasi ini, tapi server "
                                "yang mengirimnya menunjukkan misconfig serius — di reverse-"
                                "proxy / WAF tertentu, kombinasi bisa diinterpretasi reflect "
                                "Origin asli sehingga benar-benar exploitable."
                            ),
                            target=url,
                            evidence=(
                                f"OPTIONS {url}\n"
                                f"Origin sent     : {EVIL_ORIGIN}\n"
                                f"ACA-Origin      : {acao}\n"
                                f"ACA-Credentials : {pf['acac']}\n"
                                f"ACA-Methods     : {acam}\n"
                                f"ACA-Headers     : {pf['acah']}"
                            ),
                            cwe="CWE-942",
                            confidence="confirmed",
                            urls=[url],
                            remediation=(
                                "Pilih salah satu: (A) `Allow-Origin: *` TANPA credentials "
                                "untuk API publik; ATAU (B) echo Origin dari whitelist + "
                                "credentials untuk API privat. Jangan campur."
                            ),
                            references=[
                                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#credentialed_requests_and_wildcards",
                                "https://cwe.mitre.org/data/definitions/942.html",
                            ],
                        )
                    )
                elif reflect_evil and acac:
                    findings.append(
                        Finding(
                            module="cors_credentials_probe",
                            title=f"CORS: state-changing {method} reflect attacker origin + creds di {path}",
                            severity=Severity.HIGH,
                            description=(
                                f"Server mengizinkan {method} dari Origin attacker dan "
                                "membawa kredensial korban (cookie/auth header). Kombinasi "
                                "ini = CSRF-bypass terotomatisasi: halaman jahat dapat "
                                "memanggil endpoint sensitif (transfer, checkout, ganti "
                                "password) atas nama korban yang sedang login."
                            ),
                            target=url,
                            evidence=(
                                f"OPTIONS {url}\n"
                                f"ACR-Method      : {method}\n"
                                f"Origin sent     : {EVIL_ORIGIN}\n"
                                f"ACA-Origin      : {acao}  (reflect)\n"
                                f"ACA-Credentials : true\n"
                                f"ACA-Methods     : {acam}\n"
                                f"ACA-Headers     : {pf['acah']}"
                            ),
                            cwe="CWE-942",
                            confidence="confirmed",
                            urls=[url],
                            remediation=(
                                "1. Whitelist Origin yang spesifik di server-side, JANGAN "
                                "echo nilai Origin yang masuk.\n"
                                "2. Hanya endpoint yang memang dipakai cross-site (mis. "
                                "embeddable widget) yang boleh non-same-origin.\n"
                                "3. Untuk endpoint state-changing, prefer same-origin policy "
                                "+ CSRF token + SameSite=Strict cookie."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                                "https://cwe.mitre.org/data/definitions/942.html",
                            ],
                        )
                    )
                elif reflect_evil and not acac:
                    findings.append(
                        Finding(
                            module="cors_credentials_probe",
                            title=f"CORS: reflect attacker origin di {path} (state-changing {method})",
                            severity=Severity.MEDIUM,
                            description=(
                                "Server reflect Origin attacker untuk method state-changing "
                                f"`{method}`, tapi tanpa credentials. Risiko nyata: data "
                                "yang TIDAK butuh auth dapat di-fetch lintas-origin oleh "
                                "halaman jahat — leak kalau endpoint sebenarnya "
                                "mengembalikan info berdasarkan IP / cookie pihak ketiga."
                            ),
                            target=url,
                            evidence=(
                                f"OPTIONS {url}\n"
                                f"ACR-Method      : {method}\n"
                                f"ACA-Origin      : {acao}  (reflect)\n"
                                f"ACA-Credentials : false / absent\n"
                                f"ACA-Methods     : {acam}"
                            ),
                            cwe="CWE-942",
                            confidence="firm",
                            urls=[url],
                            remediation=(
                                "Whitelist Origin secara eksplisit. Tambahkan `Vary: Origin`."
                            ),
                            references=[
                                "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                            ],
                        )
                    )
                else:
                    # ACAO ada tapi bukan attacker origin -> sudah whitelist, OK
                    continue
                break  # 1 finding per path sudah cukup
    finally:
        client.close()
    return findings
