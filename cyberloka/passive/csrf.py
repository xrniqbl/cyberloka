"""Detect HTML forms without anti-CSRF tokens."""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

CSRF_TOKEN_HINTS = re.compile(
    r"csrf|xsrf|authenticity_token|__requestverificationtoken|nonce", re.I
)
SAFE_FIELDS = {"submit", "button", "image", "reset"}


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is None or not resp.text:
            return findings
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return findings

        # Cookie-based CSRF token presence (frameworks like Django/Spring/Laravel)
        cookie_blob = "; ".join(f"{c.name}" for c in resp.cookies)
        cookie_csrf = bool(CSRF_TOKEN_HINTS.search(cookie_blob))

        # SameSite cookie (Lax/Strict) provides partial CSRF protection
        same_site_cookies = []
        for raw in (resp.headers.get("Set-Cookie") or "").split(","):
            if "samesite=lax" in raw.lower() or "samesite=strict" in raw.lower():
                same_site_cookies.append(raw.split("=", 1)[0])

        for form in forms:
            method = (form.get("method") or "GET").upper()
            if method == "GET":
                continue
            action = form.get("action") or target.base_url
            inputs = form.find_all(("input", "textarea", "select"))
            input_names = [i.get("name", "") for i in inputs if i.get("type", "text") not in SAFE_FIELDS]
            html_csrf = any(CSRF_TOKEN_HINTS.search(n or "") for n in input_names)
            html_meta = bool(soup.find("meta", attrs={"name": re.compile(r"csrf", re.I)}))

            if html_csrf or html_meta or cookie_csrf:
                continue

            findings.append(
                Finding(
                    module="csrf",
                    title=f"Form POST tanpa anti-CSRF token (action={action})",
                    severity=Severity.MEDIUM,
                    description=(
                        "Form mengirim data via POST tanpa hidden token CSRF dan tidak "
                        "ada cookie CSRF terdeteksi. Permintaan ini bisa di-trigger "
                        "lintas-situs jika user korban login."
                    ),
                    target=target.base_url,
                    evidence=f"action={action}\nfields={input_names}",
                    cwe="CWE-352",
                    remediation=(
                        "Tambahkan token CSRF unik per session/form (synchronizer token "
                        "pattern), atau pakai double-submit cookie + SameSite=Lax. "
                        "Banyak framework menyediakan ini built-in (Django, Spring, "
                        "Laravel, Rails)."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                    ],
                )
            )
    finally:
        client.close()
    return findings
