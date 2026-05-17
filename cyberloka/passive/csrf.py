"""CSRF protection audit pada form yang ditemukan crawler.

Tidak melakukan exploit lintas-site. Hanya memeriksa apakah form yang
state-changing (method=POST/PUT/DELETE atau yang fields-nya berisi
sesuatu yang sensitif) memiliki:

  1) Anti-CSRF token field (csrf, _token, authenticity_token, dsb.), ATAU
  2) Cookie SameSite=Lax/Strict (mitigasi level transport), ATAU
  3) Custom header check (umumnya untuk fetch JSON; tidak terdeteksi dari HTML),

dan apakah cookies session menggunakan SameSite.

Bila form POST tidak punya token DAN cookie session tidak SameSite,
laporkan finding HIGH.
"""
from __future__ import annotations

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

CSRF_FIELD_HINTS = (
    "csrf",
    "csrfmiddlewaretoken",
    "_token",
    "authenticity_token",
    "__requestverificationtoken",
    "xsrf",
)


def _has_csrf_token(fields: list[str]) -> bool:
    return any(any(h in f.lower() for h in CSRF_FIELD_HINTS) for f in fields)


def _samesite_value(set_cookie_lines: list[str]) -> str | None:
    for line in set_cookie_lines:
        low = line.lower()
        if "samesite=strict" in low:
            return "Strict"
        if "samesite=lax" in low:
            return "Lax"
        if "samesite=none" in low:
            return "None"
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:  # noqa: ARG001
    findings: list[Finding] = []
    discovered = getattr(target, "discovered", None)
    if discovered is None or not getattr(discovered, "forms", None):
        return findings

    client = HttpClient(config)
    try:
        # Ambil cookies session dari halaman utama
        resp = client.get(target.base_url)
        sc_lines: list[str] = []
        if resp is not None:
            try:
                if hasattr(resp.raw, "headers"):
                    sc_lines = list(resp.raw.headers.getlist("Set-Cookie"))
            except Exception:  # noqa: BLE001
                sc_lines = []
            if not sc_lines:
                sc = resp.headers.get("Set-Cookie")
                sc_lines = [sc] if sc else []
        samesite = _samesite_value(sc_lines)
    finally:
        client.close()

    for form in discovered.forms:
        method = (form.get("method") or "GET").upper()
        if method == "GET":
            continue  # GET form tidak rentan CSRF state-change klasik
        fields = form.get("fields") or []
        has_token = _has_csrf_token(fields)
        if has_token:
            continue
        # Hanya laporkan jika cookie session tidak SameSite=Lax/Strict
        if samesite in ("Lax", "Strict"):
            sev = Severity.LOW
            extra_note = (
                f"Cookie session SameSite={samesite} memberi mitigasi parsial. "
                "Tetap tambahkan token CSRF eksplisit untuk operasi sensitif."
            )
        else:
            sev = Severity.HIGH
            extra_note = (
                "Tidak ada token DAN cookie session tidak SameSite — form rentan CSRF."
            )

        findings.append(
            Finding(
                module="csrf",
                title=f"Form {method} tanpa token CSRF: {form.get('url')}",
                severity=sev,
                description=(
                    f"Form state-changing tidak memiliki field anti-CSRF. {extra_note}"
                ),
                target=form.get("url", target.base_url),
                evidence=f"method={method} fields={fields} samesite={samesite}",
                cwe="CWE-352",
                remediation=(
                    "Implementasi anti-CSRF token (synchronizer pattern atau double-submit cookie). "
                    "Framework biasanya punya middleware: Django CsrfViewMiddleware, Flask-WTF, "
                    "Spring Security CSRF, ASP.NET AntiForgery. Tambahkan SameSite=Lax pada "
                    "cookie session."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/csrf",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                ],
            )
        )
    return findings
