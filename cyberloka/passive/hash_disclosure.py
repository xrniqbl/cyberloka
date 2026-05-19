"""Hash & secret disclosure scanner (passive).

Memindai response body untuk pola hash kredensial / token yang seharusnya
tidak muncul di response publik:

    * **MD5**          (32 hex)
    * **SHA-1**        (40 hex)
    * **SHA-256**      (64 hex)
    * **SHA-512**      (128 hex)
    * **bcrypt**       `$2[abxy]?$\\d{2}\\$...`
    * **scrypt**       `$scrypt$...`
    * **argon2**       `$argon2(id|i|d)\\$...`
    * **JWT**          `eyJ...\\.eyJ...\\.[A-Za-z0-9_\\-]+`
    * **MySQL hash**   `*XXXXXXX...` (41 hex caps prefix `*`)
    * **NTLM**         32-hex setelah `NTLM:` atau di body
    * **Crypt(3)**     `$1$/$5$/$6$<salt>$<hash>` (legacy unix)
    * **Django pbkdf2** `pbkdf2_sha256$...$...$...`
    * **Generic API key style** `(?:^|[^a-zA-Z0-9])[A-Za-z0-9]{32,64}` —
      hanya kalau muncul beberapa kali dan terkonteks (di JSON dengan
      key bernama `password_hash`/`hash`/`token`).

Strategi anti-false-positive:
    * Heuristik konteks: hash MD5/SHA muncul **dalam JSON dengan key**
      yang berarti (`password_hash`, `hash`, `digest`, `token`, `signature`).
      Kalau hanya angka 32-hex sembarangan (CSS hash, image hash) -> skip.
    * Tidak melaporkan single hash di header `ETag` / `If-None-Match`.
    * Maks 5 sample evidence per finding agar report tidak banjir.

Crawl beberapa URL: target root + 8 URL crawler-discovered.
"""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,}\b")
BCRYPT_RE = re.compile(r"\$2[abxy]?\$\d{2}\$[A-Za-z0-9./]{53}")
SCRYPT_RE = re.compile(r"\$scrypt\$[A-Za-z0-9+/=$,:]+")
ARGON2_RE = re.compile(r"\$argon2(?:id|i|d)\$v=\d+\$[A-Za-z0-9+/=$,:]+")
CRYPT_RE = re.compile(r"\$(?:1|2[axby]?|5|6)\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{20,}")
DJ_PBKDF2_RE = re.compile(r"pbkdf2_sha\d+\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+")
MYSQL_RE = re.compile(r"\*[A-F0-9]{40}\b")  # MySQL old_password format

# JSON context: cari "key": "value-hash"
HASH_CONTEXT_RE = re.compile(
    r'"(?P<k>password_hash|hash|digest|token|signature|api_key|apikey|'
    r'access_token|refresh_token|jwt|session|secret|nthash|lmhash)"\s*:\s*'
    r'"(?P<v>[A-Za-z0-9+/=._\-$]{16,256})"',
    re.I,
)
MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.I)
SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.I)
SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)
SHA512_RE = re.compile(r"\b[a-f0-9]{128}\b", re.I)


def _crawl_urls(target: Target, config: ScanConfig, max_n: int = 8) -> list[str]:
    out = [target.base_url]
    s = get_state(config)
    if s:
        out.extend(s.urls[:max_n])
        out.extend(s.param_urls[:max_n // 2])
    # dedupe
    seen: set[str] = set()
    uniq: list[str] = []
    for u in out:
        if u not in seen:
            seen.add(u); uniq.append(u)
    return uniq[:max_n + 1]


def _scan_body(body: str) -> dict[str, list[str]]:
    """Return {hash_label: [sample, ...]}."""
    if not body or len(body) < 16:
        return {}
    out: dict[str, list[str]] = {}

    # 1. JWT
    for m in JWT_RE.finditer(body):
        out.setdefault("JWT", []).append(m.group(0)[:60] + "...")
        if len(out["JWT"]) >= 3:
            break

    # 2. password-hash families (high confidence)
    for label, rx in (("bcrypt", BCRYPT_RE), ("argon2", ARGON2_RE),
                      ("scrypt", SCRYPT_RE), ("crypt(3)", CRYPT_RE),
                      ("Django pbkdf2", DJ_PBKDF2_RE),
                      ("MySQL old_password", MYSQL_RE)):
        for m in rx.finditer(body):
            out.setdefault(label, []).append(m.group(0)[:80])
            if len(out[label]) >= 3:
                break

    # 3. Generic hash di JSON context (paling akurat).
    for m in HASH_CONTEXT_RE.finditer(body):
        key = m.group("k").lower()
        val = m.group("v")
        # Skip kalau panjangnya tidak hash-like
        n = len(val)
        if n in (32, 40, 64, 128) and re.fullmatch(r"[a-fA-F0-9]+", val):
            label = f"{key} ({n*4}-bit hex)"
            out.setdefault(label, []).append(f"{key}={val[:20]}...")
            if len(out[label]) >= 3:
                continue
        elif n >= 20:
            label = f"{key} (token-like)"
            out.setdefault(label, []).append(f"{key}={val[:24]}...")
            if len(out[label]) >= 3:
                continue
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    seen_combo: set[tuple[str, str]] = set()
    client = HttpClient(config)
    try:
        for url in _crawl_urls(target, config):
            r = client.get(url, allow_redirects=True)
            if r is None:
                continue
            body = r.text or ""
            hits = _scan_body(body)
            for label, samples in hits.items():
                key = (url, label)
                if key in seen_combo:
                    continue
                seen_combo.add(key)
                # Severity per type
                if "bcrypt" in label or "argon2" in label or "scrypt" in label \
                        or "crypt(3)" in label or "MySQL" in label \
                        or "Django pbkdf2" in label:
                    sev = Severity.CRITICAL  # password hash bocor = serius
                elif "JWT" in label:
                    sev = Severity.HIGH
                elif "password_hash" in label or "session" in label \
                        or "secret" in label or "access_token" in label \
                        or "refresh_token" in label or "api_key" in label \
                        or "apikey" in label:
                    sev = Severity.HIGH
                else:
                    sev = Severity.MEDIUM
                findings.append(Finding(
                    module="hash_disclosure",
                    title=f"Hash/token bocor di response: {label}",
                    severity=sev,
                    description=(
                        f"Ditemukan {label} di response publik. Hash "
                        "password (bcrypt/argon2/scrypt) yang bocor "
                        "memungkinkan offline cracking. Token JWT bocor "
                        "dapat dipakai langsung untuk impersonate user. "
                        "API key bocor = pengambilalihan integrasi."
                    ),
                    target=url,
                    evidence=truncate(
                        f"samples={samples[:3]}", 240,
                    ),
                    cwe="CWE-200",
                    confidence="firm",
                    remediation=(
                        "Audit endpoint yang membalas data ini. JANGAN "
                        "pernah serialize `password_hash`, `password`, "
                        "`token`, `secret` ke response publik. Pakai "
                        "DTO/Resource layer untuk filter field. Token "
                        "yang bocor harus segera di-revoke + rotasi key."
                    ),
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                    ],
                    extra={"reverify": {"marker": samples[0][:24],
                                        "in_body": True}}
                    if samples else {},
                ))
    finally:
        client.close()
    return findings
