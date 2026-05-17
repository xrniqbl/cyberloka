"""Session management audit.

Yang dicek (non-destruktif, tanpa login):
- Session ID terlihat predictable (sequential, timestamp-based, ID pendek).
- Session ID dipassing di URL (`?sid=...`, `?PHPSESSID=...`).
- Session cookie di-set TANPA atribut keamanan dasar (sudah dicek di
  modul `cookies`, di sini kita fokus ke pola lain).
- Session ID di-set ulang ke nilai sama setelah hit beberapa kali
  → session statis (BAD), atau berubah tiap request → session fixation
  resistance OK.

Dibandingkan modul `cookies` yang fokus ke flag (Secure/HttpOnly), modul
ini fokus ke isi & pola session ID.
"""
from __future__ import annotations

import math
import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

SESSION_COOKIE_HINTS = (
    "session", "sess", "sid", "phpsessid", "jsessionid",
    "asp.net_sessionid", "connect.sid", "laravel_session", "ci_session",
    "auth", "token",
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_sequential_or_short(value: str) -> tuple[bool, str]:
    """Return (suspicious, reason)."""
    if len(value) < 12:
        return True, f"session ID terlalu pendek ({len(value)} char) — risiko brute-force"
    if value.isdigit():
        return True, "session ID hanya angka — sangat predictable"
    if re.match(r"^[a-f0-9]{8,16}$", value):
        return True, "session ID terlihat sequential/timestamp (hex pendek)"
    ent = _shannon_entropy(value)
    if ent < 3.0:
        return True, f"entropy rendah ({ent:.2f} bits/char) — kemungkinan predictable"
    return False, ""


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # 1) Cek session di URL
        resp = client.get(target.base_url)
        if resp is None:
            return findings

        # Cari pola sessionid=... di URL hasil redirect chain atau body
        body = resp.text or ""
        url_sid_re = re.compile(
            r"[?&](?:phpsessid|jsessionid|sid|sessionid)=[A-Za-z0-9_-]+",
            re.IGNORECASE,
        )
        if url_sid_re.search(body) or url_sid_re.search(resp.url or ""):
            findings.append(
                Finding(
                    module="session_audit",
                    title="Session ID dipassing lewat URL (rentan log/referer leak)",
                    severity=Severity.HIGH,
                    description=(
                        "Session ID terlihat di URL. Akan tercatat di access log "
                        "server, history browser, dan dikirim sebagai Referer ke "
                        "domain pihak ketiga (analytics, CDN, dll)."
                    ),
                    target=target.base_url,
                    evidence=truncate(url_sid_re.search(body or resp.url or "") and (url_sid_re.search(body) or url_sid_re.search(resp.url)).group(0) or "", 120),
                    cwe="CWE-598",
                    remediation=(
                        "Pindahkan session ID ke cookie HttpOnly+Secure+SameSite. "
                        "JANGAN pakai URL rewriting untuk session (mis. PHP "
                        "session.use_only_cookies=1)."
                    ),
                )
            )

        # 2) Analisa session cookie
        sc_lines: list[str] = []
        try:
            if hasattr(resp.raw, "headers"):
                sc_lines = list(resp.raw.headers.getlist("Set-Cookie"))
        except Exception:  # noqa: BLE001
            pass
        if not sc_lines:
            sc = resp.headers.get("Set-Cookie")
            sc_lines = [sc] if sc else []

        for raw in sc_lines:
            name = raw.split("=", 1)[0]
            if not any(h in name.lower() for h in SESSION_COOKIE_HINTS):
                continue
            value = raw.split("=", 1)[1].split(";", 1)[0] if "=" in raw else ""
            suspicious, reason = _is_sequential_or_short(value)
            if suspicious:
                findings.append(
                    Finding(
                        module="session_audit",
                        title=f"Session cookie `{name}` terlihat predictable: {reason}",
                        severity=Severity.HIGH,
                        description=(
                            "Session ID yang predictable memungkinkan attacker "
                            "menebak/brute-force session user lain."
                        ),
                        target=target.base_url,
                        evidence=f"value(redacted)={value[:4]}***{value[-4:] if len(value)>8 else ''} len={len(value)}",
                        cwe="CWE-330",
                        remediation=(
                            "Generate session ID dengan CSPRNG (Python: secrets.token_urlsafe(32), "
                            "Node: crypto.randomBytes(32). Min 128-bit entropy. JANGAN pakai "
                            "timestamp/incremental ID."
                        ),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                        ],
                    )
                )

        # 3) Hit ulang 3x; kalau dapat session cookie sama persis → static session
        seen_sids: list[str] = []
        for _ in range(3):
            r2 = client.get(target.base_url)
            if r2 is None:
                continue
            try:
                lines = list(r2.raw.headers.getlist("Set-Cookie")) if hasattr(r2.raw, "headers") else []
            except Exception:  # noqa: BLE001
                lines = []
            if not lines:
                sc = r2.headers.get("Set-Cookie")
                lines = [sc] if sc else []
            for raw in lines:
                name = raw.split("=", 1)[0]
                if any(h in name.lower() for h in SESSION_COOKIE_HINTS):
                    val = raw.split("=", 1)[1].split(";", 1)[0]
                    seen_sids.append(val)
                    break
        # Sebenarnya session anonim memang bisa sama; tapi kalau session lifetime
        # nya sama persis dan tidak rotate sama sekali bahkan tidak setting baru →
        # di sini kita hanya laporkan INFO supaya tidak false-positive
        if len(set(seen_sids)) == 1 and seen_sids:
            findings.append(
                Finding(
                    module="session_audit",
                    title="Session ID tidak berubah setelah beberapa request anonim",
                    severity=Severity.INFO,
                    description=(
                        "Server mengembalikan session ID yang sama untuk request anonim. "
                        "Ini biasanya OK (anonim memang tidak butuh session unik), tapi "
                        "test manual perlu memverifikasi: setelah login, apakah session "
                        "ID di-rotate? Kalau tidak, ada Session Fixation."
                    ),
                    target=target.base_url,
                ),
            )
    finally:
        client.close()
    return findings
