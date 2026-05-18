"""Stored / Persistent XSS probe pada profile fields & posts.

Berbeda dari modul `xss` (reflected) — ini fokus pada field yang DISIMPAN ke
database lalu ditampilkan ke user lain (bio, display name, comment, post).
Sangat berbahaya untuk sosmed karena bersifat WORMABLE.
"""
from __future__ import annotations

import re
import secrets

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

# Fields umum di sosmed yang dipersist ke profile/post
PROFILE_FIELDS_RE = re.compile(
    r"(bio|about|description|name|nickname|displayname|status|tagline|"
    r"signature|caption|comment|message|post|content|title|website|location)",
    re.I,
)
PROFILE_HINT = re.compile(
    r"(profile|account|setting|edit|me|user|bio|post|comment)",
    re.I,
)


def _profile_forms(config: ScanConfig) -> list[dict]:
    s = get_state(config)
    if not s:
        return []
    out = []
    for f in s.forms:
        action_low = (f.get("action") or "").lower()
        names = " ".join(i.get("name", "") for i in f["inputs"]).lower()
        if PROFILE_HINT.search(action_low) and PROFILE_FIELDS_RE.search(names):
            out.append(f)
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    forms = _profile_forms(config)
    if not forms:
        return findings
    client = HttpClient(config)
    try:
        for form in forms[:3]:
            target_field = next(
                (i for i in form["inputs"]
                 if PROFILE_FIELDS_RE.search(i.get("name", "") or "")),
                None,
            )
            if not target_field:
                continue

            marker = f"cyberloka{secrets.token_hex(4)}"
            payload = f'<sCript>document.title="{marker}"</sCript>'

            data = {
                i["name"]: payload if i is target_field else (i.get("value") or "x")
                for i in form["inputs"]
                if i.get("type") not in ("submit", "button")
            }
            method = (form.get("method") or "post").lower()
            action = form["action"]

            r = (client.post(action, data=data) if method == "post"
                 else client.get(action, params=data))
            if r is None:
                continue

            # Ambil ulang halaman profile untuk lihat apakah payload tersimpan
            r2 = client.get(action)
            if r2 is None:
                # Fallback: cek halaman utama
                r2 = client.get(target.base_url)
            if r2 is None:
                continue

            body = r2.text or ""
            if payload in body and marker in body:
                findings.append(Finding(
                    module="stored_xss",
                    target=action,
                    title=f"Stored XSS pada field `{target_field['name']}`",
                    severity=Severity.CRITICAL,
                    description=(
                        "Field profile/post menyimpan input berisi tag <script> dan "
                        "menampilkannya kembali tanpa encoding.\n\n"
                        "SKENARIO SERANGAN:\n"
                        "1. Attacker pasang payload XSS di bio/profile mereka.\n"
                        "2. Setiap user yang mengunjungi profile attacker akan "
                        "mengeksekusi script di browser mereka.\n"
                        "3. Script bisa: (a) mencuri session cookie, "
                        "(b) memasang payload yang sama di profile korban "
                        "(WORMABLE), (c) mem-follow akun attacker otomatis, "
                        "(d) DM-spam ke kontak korban.\n"
                        "4. Dalam hitungan jam, ratusan ribu akun bisa terinfeksi "
                        "(klasik: Samy worm di MySpace, 2005)."
                    ),
                    evidence=(
                        f"Field    : {target_field['name']}\n"
                        f"Payload  : {payload}\n"
                        f"Marker   : {marker} ditemukan di response GET berikutnya\n"
                        f"Verifikasi manual: buka {action} di browser dengan akun "
                        "berbeda → harus muncul popup/title berubah."
                    ),
                    cwe="CWE-79",
                    confidence="firm",
                    remediation=(
                        "LANGKAH PERBAIKAN:\n"
                        "1. Output encoding kontekstual saat render bio/profile:\n"
                        "   - HTML body → htmlspecialchars()/encode\n"
                        "   - Atribut HTML → encode quote & ampersand\n"
                        "   - JavaScript context → JSON.stringify()\n"
                        "2. Simpan input apa adanya di DB (jangan strip), tapi "
                        "ENCODE saat render.\n"
                        "3. Tambahkan Content-Security-Policy ketat:\n"
                        "   `Content-Security-Policy: default-src 'self'; "
                        "script-src 'self' 'nonce-RANDOM'`\n"
                        "4. Pakai library template yang auto-escape: \n"
                        "   - React (default), Vue (v-text bukan v-html), \n"
                        "   - Jinja autoescape, Django template, ERB <%= %>\n\n"
                        "VERIFIKASI:\n"
                        "Setelah patch, ulangi test ini dan pastikan payload "
                        "muncul sebagai TEKS (tidak dieksekusi). Cek juga di "
                        "browser DevTools — tag <script> harus ter-escape "
                        "menjadi `&lt;script&gt;`."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        "https://en.wikipedia.org/wiki/Samy_(computer_worm)",
                    ],
                ))
                return findings
    finally:
        client.close()
    return findings
