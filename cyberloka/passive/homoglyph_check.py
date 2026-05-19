"""Detect homoglyph / look-alike usernames + brand impersonation."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

# Cyrillic / Greek letters yang look-alike Latin
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C",
    "Х": "X", "У": "Y", "ѕ": "s", "і": "i", "ј": "j", "ӏ": "l",
    "ɑ": "a", "ɡ": "g", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p",
}
USERNAME_RE = re.compile(r"@([A-Za-z0-9_\u0400-\u04FF\u0370-\u03FF\u02B0-\u02FF]{3,30})")


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings

    suspicious = []
    client = HttpClient(config)
    try:
        # Scan bodies for usernames
        for url in [target.base_url] + s.urls[:5]:
            r = client.get(url)
            if r is None:
                continue
            body = r.text or ""
            for m in USERNAME_RE.finditer(body):
                handle = m.group(1)
                if any(c in HOMOGLYPHS for c in handle):
                    normalized = "".join(HOMOGLYPHS.get(c, c) for c in handle)
                    suspicious.append((handle, normalized))

        # Dedupe
        seen = set()
        unique = []
        for h, n in suspicious:
            if h not in seen:
                seen.add(h); unique.append((h, n))
        suspicious = unique

        if suspicious:
            findings.append(Finding(
                module="homoglyph_check",
                target=target.base_url,
                title=(
                    f"{len(suspicious)} handle/username mengandung karakter "
                    "look-alike (homoglyph)"
                ),
                severity=Severity.MEDIUM,
                description=(
                    "Sistem registrasi mengizinkan username dengan karakter "
                    "Cyrillic/Greek yang TERLIHAT identik dengan huruf Latin.\n\n"
                    "SKENARIO SERANGAN:\n"
                    "1. Brand resmi memakai @starbucks (semua huruf Latin).\n"
                    "2. Attacker daftar @stаrbucks (huruf 'а' Cyrillic, "
                    "U+0430) — terlihat sama persis di mata user.\n"
                    "3. Attacker post promo/giveaway palsu, follower brand "
                    "asli mengira itu official.\n"
                    "4. Korban klik link phishing → kredensial dicuri.\n"
                    "5. Dampak: kerusakan reputasi brand + kerugian pelanggan."
                ),
                evidence="\n".join(
                    f"@{h} (normalisasi → @{n})" for h, n in suspicious[:8]
                ),
                cwe="CWE-1007",
                remediation=(
                    "LANGKAH PERBAIKAN:\n"
                    "1. Saat registrasi, REJECT username yang memuat karakter "
                    "non-ASCII look-alike. Whitelist: `[a-zA-Z0-9_]` saja.\n"
                    "2. Pakai library `confusable_homoglyphs` di Python atau "
                    "`@unicode/properties` di JS:\n"
                    "   ```python\n"
                    "   from confusable_homoglyphs import confusables\n"
                    "   if confusables.is_confusable(username, greedy=True):\n"
                    "       raise ValueError('Username mengandung karakter "
                    "yang menyerupai huruf lain')\n"
                    "   ```\n"
                    "3. Saat menampilkan, normalize dengan NFKC dan tampilkan "
                    "warning kalau username tidak ASCII murni.\n"
                    "4. Untuk brand verified, tag dengan badge ✓ — homoglyph "
                    "tidak akan dapat badge (karena verified manual).\n\n"
                    "VERIFIKASI:\n"
                    "Coba register dengan @stаrbucks (а Cyrillic). Form harus "
                    "REJECT dengan pesan 'username mengandung karakter tidak "
                    "valid'."
                ),
                references=[
                    "https://www.unicode.org/reports/tr39/",
                    "https://owasp.org/www-community/attacks/Phishing",
                ],
            ))
    finally:
        client.close()
    return findings
