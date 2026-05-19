"""Direct-message endpoint privacy probe."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

DM_HINTS = re.compile(
    r"(dm|direct[-_]?message|message|chat|conversation|inbox|pesan)",
    re.I,
)
COMMON_DM_PATHS = [
    "/api/messages", "/api/v1/messages", "/api/dm", "/api/v1/dm",
    "/api/inbox", "/api/conversations", "/api/v1/conversations",
    "/messages", "/dm",
]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    candidates = set()
    s = get_state(config)
    if s:
        for u in s.urls + s.param_urls:
            if DM_HINTS.search(u):
                candidates.add(u)
    for p in COMMON_DM_PATHS:
        candidates.add(urljoin(target.origin + "/", p.lstrip("/")))

    client = HttpClient(config)
    try:
        for url in list(candidates)[:8]:
            # 1. Akses tanpa auth — harus 401/403
            r_anon = client.get(url)
            if r_anon is None or r_anon.status_code >= 500:
                continue
            ctype = (r_anon.headers.get("Content-Type") or "").lower()

            # Kalau dapat 200 + JSON dari endpoint DM tanpa login = bocor
            if r_anon.status_code == 200 and "json" in ctype:
                body = r_anon.text or ""
                # Periksa isi: mengandung pola message
                if re.search(
                    r'"(content|body|text|message|sender|recipient)"\s*:',
                    body, re.I
                ):
                    findings.append(Finding(
                        module="dm_privacy",
                        target=url,
                        title=f"Endpoint DM bocor TANPA autentikasi: {url}",
                        severity=Severity.CRITICAL,
                        description=(
                            "Endpoint Direct Message dapat diakses oleh "
                            "pengunjung anonim dan mengembalikan isi pesan "
                            "private antar user.\n\n"
                            "SKENARIO SERANGAN:\n"
                            "1. Attacker scrape endpoint DM tanpa login (cukup "
                            "`curl <url>`).\n"
                            "2. Mendapat seluruh percakapan private user — "
                            "termasuk pesan yang sangat sensitif "
                            "(pribadi, bisnis, romantis, dll).\n"
                            "3. Kebocoran skala besar bisa jadi headline berita "
                            "(klasik: kebocoran DM Twitter/X 2020).\n"
                            "4. Pelanggaran besar UU PDP dan ITE."
                        ),
                        evidence=(
                            f"GET {url} (tanpa cookie/auth)\n"
                            f"Status   : {r_anon.status_code}\n"
                            f"Content  : JSON dengan field 'content'/'sender'/etc.\n"
                            f"Length   : {len(body)} bytes"
                        ),
                        cwe="CWE-306",
                        confidence="firm",
                        remediation=(
                            "LANGKAH PERBAIKAN:\n"
                            "1. SEMUA endpoint DM WAJIB auth middleware:\n"
                            "   ```python\n"
                            "   @login_required\n"
                            "   def get_messages(request):\n"
                            "       return Message.objects.filter(\n"
                            "           Q(sender=request.user) | \n"
                            "           Q(recipient=request.user)\n"
                            "       )\n"
                            "   ```\n"
                            "2. Filter di QUERY DATABASE — jangan trust "
                            "filtering di sisi client.\n"
                            "3. Encrypt at rest dengan key per-user (kalau "
                            "memungkinkan E2E encryption).\n"
                            "4. Audit log: catat siapa membaca DM siapa.\n"
                            "5. Rate-limit endpoint DM untuk mencegah scraping.\n\n"
                            "VERIFIKASI:\n"
                            "  curl <endpoint>  # tanpa cookie\n"
                            "  → harus 401 Unauthorized atau 403 Forbidden.\n"
                            "  curl -H 'Cookie: session=user_A' <endpoint>?user=user_B\n"
                            "  → harus return DM milik user_A SAJA, BUKAN user_B."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                        ],
                    ))
                    return findings

            # 2. Authenticated tapi tidak filter — ganti user_id di query
            if "user" in url.lower() or "?" in url:
                # Coba pakai user_id berbeda
                from urllib.parse import parse_qsl, urlencode, urlunparse
                from urllib.parse import urlparse as uparse
                p = uparse(url)
                params = list(parse_qsl(p.query))
                for i, (k, v) in enumerate(params):
                    if k.lower() in ("user_id", "userid", "uid", "to"):
                        params[i] = (k, "1" if v != "1" else "2")
                        new = urlunparse(p._replace(query=urlencode(params)))
                        r2 = client.get(new)
                        if r2 is not None and r2.status_code == 200:
                            b = r2.text or ""
                            if re.search(r'"(content|body|message)"', b, re.I):
                                findings.append(Finding(
                                    module="dm_privacy",
                                    target=new,
                                    title="DM endpoint dapat diakses dengan user_id orang lain",
                                    severity=Severity.HIGH,
                                    description=(
                                        "IDOR pada endpoint DM — mengubah "
                                        "user_id di URL menghasilkan pesan "
                                        "user lain."
                                    ),
                                    evidence=f"GET {new} → 200 dengan content message",
                                    cwe="CWE-639",
                                    remediation=(
                                        "Filter berdasarkan `request.user.id` "
                                        "di server — jangan trust user_id dari "
                                        "query string."
                                    ),
                                ))
                                return findings
    finally:
        client.close()
    return findings
