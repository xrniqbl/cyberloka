"""Account enumeration detector.

Cek apakah login & forgot-password endpoint memberi response berbeda
antara "user valid + password salah" vs "user tidak ada".

Strategi:
- Discover login & forgot-password endpoint dari crawler.
- Kirim 2 request:
  (A) email yang JELAS-tidak-ada: noexist-cyberloka-{rand}@nowhere.invalid
  (B) email yang plausibel: admin@<target_domain>
- Bandingkan response: status code, length, key-phrase.
- Bila signifikan beda, account enumeration mungkin ada.

NOTE: kita tidak login real — hanya kirim 1 percobaan dengan password
random yang pasti salah. Tidak bypass apapun.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

LOGIN_HINTS = ("login", "signin", "sign-in", "auth/login", "masuk")
FORGOT_HINTS = ("forgot", "reset", "lupa-password", "lupa_password", "recover")


def _candidate_endpoints(target: Target) -> tuple[list[str], list[str]]:
    """Return (login_urls, forgot_urls)."""
    discovered = getattr(target, "discovered", None)
    login: list[str] = []
    forgot: list[str] = []
    if discovered is None:
        return login, forgot
    for ep in getattr(discovered, "endpoints", []):
        if ep.method.upper() != "POST":
            continue
        low = ep.url.lower()
        if any(h in low for h in LOGIN_HINTS):
            login.append(ep.url)
        elif any(h in low for h in FORGOT_HINTS):
            forgot.append(ep.url)
    # Cek juga form yang punya field 'password' / 'email'
    for f in getattr(discovered, "forms", []):
        if f.get("method", "GET").upper() != "POST":
            continue
        fields = [x.lower() for x in (f.get("fields") or [])]
        if any("password" in fld for fld in fields) and any("email" in fld or "username" in fld or "user" in fld for fld in fields):
            url = f.get("url", "")
            if any(h in url.lower() for h in LOGIN_HINTS):
                login.append(url)
        if any("email" in fld for fld in fields) and not any("password" in fld for fld in fields):
            if any(h in (f.get("url", "")).lower() for h in FORGOT_HINTS):
                forgot.append(f.get("url", ""))
    return list(dict.fromkeys(login)), list(dict.fromkeys(forgot))


def _normalize_resp(text: str) -> str:
    # remove csrf token / nonce / dynamic id supaya dua response dapat
    # dibandingkan secara stabil
    text = re.sub(r'(name=["\']csrf[a-zA-Z_]*["\'][^>]*value=["\'])[^"\']+', r'\1XXX', text, flags=re.IGNORECASE)
    text = re.sub(r'value=["\'][a-f0-9]{16,}["\']', 'value="HEX"', text)
    return text


def _compare(client: HttpClient, url: str, body_a: dict, body_b: dict) -> tuple[Finding | None, str]:
    """Send POST with body_a then body_b. Return finding if differ significantly."""
    r1 = client.post(url, data=body_a, allow_redirects=False)
    r2 = client.post(url, data=body_b, allow_redirects=False)
    if r1 is None or r2 is None:
        return None, ""

    # Bandingkan status code
    if r1.status_code != r2.status_code:
        return Finding(
            module="account_enum",
            title=f"Account enumeration via status code di {url}",
            severity=Severity.MEDIUM,
            description=(
                "Status HTTP berbeda saat user valid vs tidak ada. Attacker dapat "
                "menebak username/email yang valid lewat probe massal."
            ),
            target=url,
            evidence=f"existing_user={r1.status_code} non_existent={r2.status_code}",
            cwe="CWE-203",
        ), "status"

    # Bandingkan size
    body1 = _normalize_resp(r1.text or "")
    body2 = _normalize_resp(r2.text or "")
    delta = abs(len(body1) - len(body2))
    if delta > 50 and delta / max(len(body1), len(body2), 1) > 0.05:
        return Finding(
            module="account_enum",
            title=f"Account enumeration via response size di {url}",
            severity=Severity.MEDIUM,
            description=(
                "Ukuran response berbeda signifikan saat user valid vs tidak ada. "
                "Attacker dapat membedakan username valid lewat panjang body."
            ),
            target=url,
            evidence=f"existing_len={len(body1)} non_existent_len={len(body2)} delta={delta}",
            cwe="CWE-203",
        ), "size"

    # Bandingkan key-phrase
    msg_distinct = re.compile(
        r"(user\s*not\s*found|email\s*not\s*registered|tidak\s*terdaftar|"
        r"akun\s*tidak\s*ditemukan|incorrect\s*password|password\s*salah|"
        r"belum\s*terdaftar|sudah\s*terdaftar)",
        re.IGNORECASE,
    )
    m1 = msg_distinct.search(body1)
    m2 = msg_distinct.search(body2)
    if (m1 and not m2) or (m2 and not m1) or (m1 and m2 and m1.group(0).lower() != m2.group(0).lower()):
        return Finding(
            module="account_enum",
            title=f"Account enumeration via pesan error di {url}",
            severity=Severity.MEDIUM,
            description=(
                "Pesan error membedakan 'user tidak ada' vs 'password salah'. "
                "Attacker mengetahui username valid lewat pesan ini."
            ),
            target=url,
            evidence=f"existing_msg='{m1.group(0) if m1 else '-'}' non_existent_msg='{m2.group(0) if m2 else '-'}'",
            cwe="CWE-203",
        ), "message"
    return None, ""


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    login_urls, forgot_urls = _candidate_endpoints(target)
    if not login_urls and not forgot_urls:
        return findings

    client = HttpClient(config)
    try:
        domain = urlparse(target.base_url).hostname or "example.com"
        plausible = f"admin@{domain}"
        nope = f"noexist-cyberloka-{secrets.token_hex(4)}@nowhere.invalid"

        # Login: butuh field email + password
        for url in login_urls[:2]:
            body_a = {"email": plausible, "username": plausible, "password": "InvalidPassword123!"}
            body_b = {"email": nope, "username": nope, "password": "InvalidPassword123!"}
            finding, _why = _compare(client, url, body_a, body_b)
            if finding:
                findings.append(finding)

        # Forgot password
        for url in forgot_urls[:2]:
            body_a = {"email": plausible}
            body_b = {"email": nope}
            finding, _why = _compare(client, url, body_a, body_b)
            if finding:
                # Lebih kritis di forgot: ideally forgot HARUS return generic message
                finding.severity = Severity.MEDIUM
                finding.title = finding.title.replace("di ", "di forgot-password endpoint ")
                finding.remediation = (
                    "Forgot-password HARUS return pesan generik untuk semua kasus, mis. "
                    "'Jika email terdaftar, instruksi reset akan dikirim'. JANGAN beda "
                    "respons untuk email valid vs tidak."
                )
                findings.append(finding)
    finally:
        client.close()
    return findings
