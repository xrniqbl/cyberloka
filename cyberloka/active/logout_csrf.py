"""Logout CSRF / GET-based logout audit."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

LOGOUT_HINTS = re.compile(r"(logout|signout|sign-out|keluar)", re.I)
COMMON_PATHS = ["/logout", "/signout", "/auth/logout", "/api/logout",
                "/api/auth/logout", "/keluar"]


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    candidates = set()
    s = get_state(config)
    if s:
        for u in s.urls:
            if LOGOUT_HINTS.search(u):
                candidates.add(u)
    for p in COMMON_PATHS:
        candidates.add(urljoin(target.origin + "/", p.lstrip("/")))

    client = HttpClient(config)
    try:
        for url in list(candidates)[:6]:
            r = client.get(url, allow_redirects=False)
            if r is None:
                continue
            # Logout via GET + sukses (3xx redirect) = CSRF logout
            if r.status_code in (200, 302, 303):
                # Cek apakah cookie sesi diclear
                set_cookie = r.headers.get("Set-Cookie", "")
                if "Max-Age=0" in set_cookie or "expires=Thu, 01 Jan 1970" in set_cookie.lower():
                    findings.append(Finding(
                        module="logout_csrf", target=url,
                        title=f"Endpoint logout diakses lewat GET: {url}",
                        severity=Severity.LOW,
                        description=("Logout via GET dapat dipicu cross-site (mis. lewat tag image dengan src ke /logout). "
                                     "Bukan kerentanan kritikal tapi mengganggu UX dan bisa "
                                     "dipakai sebagai stage phishing."),
                        evidence=f"GET status={r.status_code}, cookie cleared",
                        cwe="CWE-352",
                        remediation=("Gunakan POST + CSRF token untuk logout. Atau minimal "
                                     "verifikasi `Origin` header."),
                    ))
                    return findings
    finally:
        client.close()
    return findings
