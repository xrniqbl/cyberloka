"""JSON CSRF — POST JSON lintas-origin via text/plain trick.

REST API yang menerima JSON body sering dianggap "kebal CSRF" karena browser
tidak mengirim ``Content-Type: application/json`` cross-origin tanpa preflight.
Tapi attacker bisa kirim form submission dengan ``Content-Type: text/plain``
dan body berisi JSON yang valid — banyak framework Express/Flask/Spring tetap
parse body itu (atau backend punya parser yang permisif).

Modul ini:
1. Discover endpoint API umum dari crawler (bila ada) atau probe path POST
   tipikal (/api/profile, /api/comment, /api/order, /api/follow).
2. Kirim POST dengan ``Content-Type: text/plain`` + body JSON harmless
   (mis. ``{"_test": "csrf-probe"}``).
3. Kalau server tetap balas 200/201/204 (tidak 415 Unsupported Media Type
   dan tidak 401/403), classify sebagai indikasi CSRF JSON.

Tindakan TIDAK destruktif: kita tidak menulis data; field ``_test`` adalah
key yang tidak diharapkan, jadi server seharusnya validasi schema dan reject.
Kalau lolos = bug.
"""
from __future__ import annotations

import json
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

CANDIDATE_PATHS = [
    "/api/profile", "/api/user", "/api/account",
    "/api/comment", "/api/comments", "/api/post", "/api/posts",
    "/api/follow", "/api/friend",
    "/api/order", "/api/cart", "/api/checkout",
    "/api/feedback", "/api/contact",
    "/api/v1/profile", "/api/v1/comment", "/api/v1/post",
    "/api/v2/profile", "/api/v2/comment", "/api/v2/post",
    "/graphql",
]

# Body yang harmless tapi cukup untuk picu parsing
PROBE_BODY = json.dumps({"_cyberloka_csrf_probe": "non-destructive-test"})


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

            # Probe 1: kirim text/plain + body JSON; tanpa Origin (simulate cross-site)
            r = client.post(
                url,
                data=PROBE_BODY,
                headers={"Content-Type": "text/plain;charset=UTF-8"},
                allow_redirects=False,
            )
            if r is None:
                continue
            status = r.status_code

            # Outcome interpretation:
            # 415 / 406 / 400 -> server reject content-type asing -> aman
            # 401 / 403 -> auth wall -> tidak vulnerable lewat CSRF tanpa cookie
            # 404 -> path tidak ada
            # 200/201/204/422 -> server PARSE body -> potensial CSRF
            if status in (415, 406, 405, 404, 401, 403):
                continue
            if status not in (200, 201, 204, 422):
                continue

            # Konfirmasi: kirim sekali lagi dengan body JSON yang lebih spesifik
            # supaya yakin server beneran route ke endpoint kita
            confirm_body = json.dumps({"test": True, "csrf_probe": "cyberloka"})
            r2 = client.post(
                url,
                data=confirm_body,
                headers={"Content-Type": "text/plain;charset=UTF-8"},
                allow_redirects=False,
            )
            if r2 is None or r2.status_code != status:
                continue

            findings.append(
                Finding(
                    module="json_csrf",
                    title=f"Endpoint JSON menerima text/plain (potensi CSRF) di {path}",
                    severity=Severity.MEDIUM,
                    description=(
                        "Endpoint POST menerima body JSON ketika Content-Type diset "
                        "`text/plain`. Browser TIDAK melakukan CORS preflight untuk "
                        "Content-Type 'simple', sehingga halaman attacker dapat memancing "
                        "form submission cross-site (lewat `<form enctype='text/plain'>` "
                        "atau `fetch({mode:'no-cors'})`) dan body JSON tetap diproses "
                        "server. Kombinasi dengan cookie sesi (SameSite=None / Lax + GET "
                        "subsequent) = CSRF nyata pada API yang dianggap aman."
                    ),
                    target=url,
                    evidence=(
                        f"POST {url}\n"
                        f"Content-Type: text/plain\n"
                        f"Body: {PROBE_BODY}\n"
                        f"Response: HTTP {status}\n"
                        f"Body snippet:\n{truncate(r.text or '', 240)}"
                    ),
                    cwe="CWE-352",
                    confidence="firm",
                    urls=[url],
                    remediation=(
                        "1. Tolak request yang Content-Type-nya bukan "
                        "`application/json` (HTTP 415).\n"
                        "2. Wajibkan CSRF token (header X-CSRF-Token) untuk endpoint "
                        "yang merubah state.\n"
                        "3. Set cookie sesi `SameSite=Strict` / `Lax` (default modern).\n"
                        "4. Validasi `Origin` / `Referer` di server-side untuk endpoint "
                        "kritis."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/csrf",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/352.html",
                    ],
                )
            )
    finally:
        client.close()
    return findings
