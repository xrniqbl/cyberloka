"""Password reset flow audit (safe heuristics)."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

RESET_HINTS = re.compile(
    r"forgot[-_]?password|reset[-_]?password|lupa[-_]?password|lupa[-_]?sandi|recovery|forgot",
    re.I,
)
EMAIL_FIELDS = re.compile(r"email|username|user|account", re.I)
TOKEN_PARAMS = ("token", "code", "key", "t", "reset", "verify")


def _candidate_urls(target: Target, config: ScanConfig) -> list[str]:
    urls = set()
    state = get_state(config)
    if state:
        for u in state.urls:
            if RESET_HINTS.search(u):
                urls.add(u)
    for path in ("/forgot-password", "/reset-password", "/lupa-password",
                 "/account/forgot", "/auth/forgot", "/api/auth/forgot",
                 "/api/password/forgot", "/api/password/reset"):
        urls.add(urljoin(target.origin + "/", path))
    return list(urls)[:12]


def _reset_forms(config: ScanConfig) -> list[dict]:
    state = get_state(config)
    if not state:
        return []
    out = []
    for f in state.forms:
        action_low = (f.get("action") or "").lower()
        if RESET_HINTS.search(action_low):
            out.append(f)
            continue
        names = " ".join(i.get("name", "") for i in f["inputs"]).lower()
        # Form lupa password biasanya hanya punya 1 field email
        if EMAIL_FIELDS.search(names) and not any(
            i.get("type") == "password" for i in f["inputs"]
        ) and len([i for i in f["inputs"] if i.get("type") not in ("hidden", "submit", "button")]) <= 2:
            out.append(f)
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # 1. User enumeration via response berbeda
        forms = _reset_forms(config)
        for form in forms[:2]:
            email_field = next(
                (i["name"] for i in form["inputs"]
                 if EMAIL_FIELDS.search(i.get("name", "") or "")),
                None,
            )
            if not email_field:
                continue
            base = {i["name"]: (i.get("value") or "x") for i in form["inputs"]
                    if i.get("type") not in ("submit", "button")}
            method = (form.get("method") or "post").lower()
            r1 = (client.post(form["action"], data={**base, email_field: "admin@example.com"})
                  if method == "post"
                  else client.get(form["action"], params={**base, email_field: "admin@example.com"}))
            r2 = (client.post(form["action"], data={**base, email_field: "no-such-user-cyberloka@example.invalid"})
                  if method == "post"
                  else client.get(form["action"], params={**base, email_field: "no-such-user-cyberloka@example.invalid"}))
            if r1 is None or r2 is None:
                continue
            b1, b2 = (r1.text or ""), (r2.text or "")
            if (r1.status_code != r2.status_code) or abs(len(b1) - len(b2)) > 200:
                findings.append(Finding(
                    module="password_reset",
                    title="Forgot-password merespons berbeda untuk user valid vs invalid",
                    severity=Severity.MEDIUM,
                    description=("Halaman lupa password menampilkan respons berbeda untuk "
                                 "email yang ada vs tidak ada. Berisiko enumerasi akun."),
                    target=form.get("action", ""),
                    evidence=f"status: {r1.status_code} vs {r2.status_code}; len: {len(b1)} vs {len(b2)}",
                    cwe="CWE-204", confidence="tentative",
                    remediation=("Selalu tampilkan pesan generik: 'Jika email terdaftar, "
                                 "kami sudah mengirim link reset.' Pastikan response dan timing sama."),
                ))

        # 2. Token via GET parameter (rentan leak Referer / log) + missing https
        for url in _candidate_urls(target, config):
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code >= 500:
                continue
            body = (r.text or "")
            # Apakah halaman menerima token via query string?
            if any(f"name=\"{p}\"" in body.lower() for p in TOKEN_PARAMS) and "?" in url:
                findings.append(Finding(
                    module="password_reset",
                    title="Token reset password kemungkinan dikirim via URL/Referer",
                    severity=Severity.MEDIUM,
                    description=("Token reset di parameter URL dapat bocor lewat header "
                                 "Referer ke domain pihak ketiga, log proxy, atau analitik."),
                    target=url, cwe="CWE-598", confidence="tentative",
                    remediation=("Kirim token via POST body atau header. Tambahkan "
                                 "`Referrer-Policy: no-referrer`, dan invalidate token "
                                 "setelah satu kali pakai."),
                ))
                break
            # Login page lupa password via HTTP?
            if r.url.startswith("http://") and target.scheme == "https":
                findings.append(Finding(
                    module="password_reset",
                    title="Endpoint reset password redirect/disajikan via HTTP",
                    severity=Severity.HIGH,
                    description="Token & email dapat disadap di jaringan.",
                    target=url, cwe="CWE-319",
                    remediation="Paksa HTTPS; aktifkan HSTS dengan `includeSubDomains; preload`.",
                ))
    finally:
        client.close()
    return findings
