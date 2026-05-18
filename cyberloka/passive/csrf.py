"""CSRF posture audit on discovered forms + cookie SameSite."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

TOKEN_NAMES = re.compile(
    r"csrf|xsrf|authenticity_token|__requestverificationtoken|csrfmiddlewaretoken",
    re.I,
)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    state = get_state(config)
    if state and state.forms:
        for form in state.forms:
            if form["method"] != "post":
                continue
            has_token = any(TOKEN_NAMES.search(i["name"] or "") for i in form["inputs"])
            if not has_token:
                findings.append(
                    Finding(
                        module="csrf",
                        title=f"Form POST tanpa CSRF token: {form['action']}",
                        severity=Severity.MEDIUM,
                        description=(
                            "Form POST tidak memuat token anti-CSRF. Penyerang dapat "
                            "memicu aksi atas nama korban dari situs lain."
                        ),
                        target=form["action"],
                        evidence=", ".join(i["name"] for i in form["inputs"]) or "(no fields)",
                        cwe="CWE-352",
                        remediation=(
                            "Tambahkan token CSRF (per-session, unguessable) yang divalidasi "
                            "server-side. Set cookie sesi `SameSite=Lax` atau `Strict` dan "
                            "verifikasi header `Origin`/`Referer`."
                        ),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                        ],
                    )
                )

    # cookie-level SameSite check
    client = HttpClient(config)
    try:
        resp = client.get(target.base_url)
        if resp is not None:
            for cookie in resp.cookies:
                rest = getattr(cookie, "_rest", {}) or {}
                samesite = (rest.get("SameSite") or rest.get("samesite") or "").lower()
                if not samesite or samesite == "none":
                    findings.append(
                        Finding(
                            module="csrf",
                            title=f"Cookie `{cookie.name}` tanpa SameSite yang aman",
                            severity=Severity.LOW,
                            description=(
                                "Cookie sesi tanpa `SameSite=Lax/Strict` mempermudah CSRF "
                                "lintas-situs."
                            ),
                            target=target.base_url,
                            evidence=f"SameSite={samesite or '(missing)'}",
                            cwe="CWE-1275",
                            remediation="Tambahkan atribut `SameSite=Lax` (atau Strict) pada cookie sesi.",
                        )
                    )
    finally:
        client.close()
    return findings
