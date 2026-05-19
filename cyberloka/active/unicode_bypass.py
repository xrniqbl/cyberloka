"""Content moderation bypass via Unicode tricks."""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

# Posting / comment forms
POST_HINTS = re.compile(r"(post|comment|reply|status|message|tweet)", re.I)


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    s = get_state(config)
    if not s:
        return findings

    forms = []
    for f in s.forms:
        if POST_HINTS.search(f.get("action") or "") and any(
            (i.get("type") or "").lower() in ("text", "textarea", "")
            for i in f["inputs"]
        ):
            forms.append(f)
    if not forms:
        return findings

    client = HttpClient(config)
    try:
        for form in forms[:2]:
            text_field = next(
                (i for i in form["inputs"]
                 if (i.get("type") or "").lower() in ("text", "textarea")),
                None,
            )
            if not text_field:
                continue

            base = {
                i["name"]: (i.get("value") or "x")
                for i in form["inputs"]
                if i.get("type") not in ("submit", "button")
            }
            method = (form.get("method") or "post").lower()
            action = form["action"]

            # Test 1: kata blacklist + zero-width char di tengah
            payloads = [
                # Zero-width space di antara huruf
                "spam\u200bword",
                # Cyrillic look-alike
                "spаm",
                # Right-to-left override (jadi terlihat normal di depan, tapi binary terbalik)
                "test\u202etset",
                # NULL byte
                "spam\x00word",
            ]

            accepted = []
            for p in payloads:
                data = {**base, text_field["name"]: p}
                r = (client.post(action, data=data) if method == "post"
                     else client.get(action, params=data))
                if r is None:
                    continue
                body = (r.text or "").lower()
                # Diterima = tidak ada error rejection
                rejected_markers = ("rejected", "blocked", "tidak diizinkan",
                                    "moderasi", "spam detected", "filtered")
                if r.status_code in (200, 201, 302) and not any(
                    m in body for m in rejected_markers
                ):
                    accepted.append(p)

            if len(accepted) >= 2:
                findings.append(Finding(
                    module="unicode_bypass",
                    target=action,
                    title=(
                        "Content moderation tampak dapat di-bypass dengan "
                        "Unicode tricks"
                    ),
                    severity=Severity.MEDIUM,
                    description=(
                        "Form post/comment menerima konten yang menggunakan "
                        "zero-width space, homoglyph, RTL override, atau NULL "
                        "byte di tengah kata.\n\n"
                        "SKENARIO SERANGAN:\n"
                        "1. Sosmed punya filter kata 'spam', 'judi', 'porno', "
                        "dst.\n"
                        "2. Attacker post 'spа\u200bm' (Cyrillic 'a' + "
                        "zero-width space).\n"
                        "3. Filter regex `\\bspam\\b` GAGAL deteksi.\n"
                        "4. Tapi user lain MEMBACA 'spam' (visual identik).\n"
                        "5. Hasil: spam massal lolos moderasi, abuse "
                        "(harassment) lolos, link phishing lolos.\n"
                        "6. Konten illegal (judi, narkoba, porno) bebas "
                        "tersebar."
                    ),
                    evidence=(
                        f"Form: {action}\n"
                        f"Payloads diterima ({len(accepted)}):\n"
                        + "\n".join(
                            f"  - {repr(p)}" for p in accepted[:4]
                        )
                    ),
                    cwe="CWE-176",
                    confidence="tentative",
                    remediation=(
                        "LANGKAH PERBAIKAN:\n"
                        "1. Sebelum filter konten, NORMALISASI:\n"
                        "   ```python\n"
                        "   import unicodedata\n"
                        "   def normalize(text):\n"
                        "       # NFKC: compose + compatibility (Cyrillic→Latin look-alike)\n"
                        "       text = unicodedata.normalize('NFKC', text)\n"
                        "       # Strip zero-width characters\n"
                        "       text = re.sub(r'[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u206F]', '', text)\n"
                        "       # Strip control characters\n"
                        "       text = ''.join(c for c in text if not unicodedata.category(c).startswith('C'))\n"
                        "       return text.lower()\n"
                        "   ```\n"
                        "2. Filter SETELAH normalisasi.\n"
                        "3. Pakai library spesialis: `confusable-homoglyphs`, "
                        "`fastText`, atau Google Perspective API untuk "
                        "moderation kontekstual.\n"
                        "4. Saat menyimpan ke DB, simpan VERSI NORMAL untuk "
                        "indexing/search, simpan ASLI untuk display.\n\n"
                        "VERIFIKASI:\n"
                        "Setelah patch, post ulang payload-payload di atas. "
                        "Filter harus DETEKSI dan reject."
                    ),
                    references=[
                        "https://www.unicode.org/reports/tr39/",
                        "https://owasp.org/www-community/attacks/Bypass_content_filtering",
                    ],
                ))
                return findings
    finally:
        client.close()
    return findings
