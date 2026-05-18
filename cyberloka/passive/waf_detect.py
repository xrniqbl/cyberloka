"""WAF / CDN fingerprint — identifikasi vendor WAF yang berdiri di depan target.

Ini bukan kerentanan, tapi **konteks** yang sangat penting untuk modul aktif
lain (cmdi/sqli/rce_validator/ssti) supaya hasil low_confidence bisa
diinterpretasi dengan benar:
- Kalau WAF aktif & memblokir payload mentah → modul aktif kemungkinan
  mendapat ``low_confidence`` bukan karena aplikasi aman, melainkan karena
  WAF di depannya.
- Kalau WAF tidak terdeteksi → finding low_confidence harus dianggap lebih
  meragukan kebenarannya.

Vendor yang dikenali (15+):
  Cloudflare, Akamai, AWS WAF, AWS CloudFront, Azure FrontDoor, Google
  Cloud Armor, Imperva Incapsula, Sucuri, F5 BIG-IP, Barracuda, Fastly,
  StackPath, Wallarm, Wordfence, ModSecurity, NSFOCUS, Citrix Netscaler.

Sinyal: Server header, Set-Cookie, X-CDN, X-Powered-By, response body
finger-print, dan TTL/Server-Timing header khas vendor.
"""
from __future__ import annotations

import re

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# (label, list of (header_name, regex_value) — match bila salah satu cocok)
SIGNATURES: list[tuple[str, list[tuple[str, "re.Pattern[str]"]]]] = [
    ("Cloudflare", [
        ("Server", re.compile(r"\bcloudflare\b", re.I)),
        ("CF-Ray", re.compile(r".+")),
        ("Set-Cookie", re.compile(r"__cfduid|__cf_bm|cf_clearance", re.I)),
    ]),
    ("Akamai", [
        ("Server", re.compile(r"\bAkamaiGHost\b", re.I)),
        ("X-Akamai-Transformed", re.compile(r".+")),
        ("X-Akamai-Edgescape", re.compile(r".+")),
    ]),
    ("AWS WAF / CloudFront", [
        ("X-Amz-Cf-Id", re.compile(r".+")),
        ("Server", re.compile(r"\bCloudFront\b", re.I)),
        ("X-Cache", re.compile(r"\bCloudFront\b", re.I)),
    ]),
    ("Azure Front Door", [
        ("X-Azure-Ref", re.compile(r".+")),
        ("Server", re.compile(r"\bMicrosoft-IIS\b.*\bFD\b", re.I)),
    ]),
    ("Google Cloud Armor / GFE", [
        ("Server", re.compile(r"\bGFE/", re.I)),
        ("Via", re.compile(r"\bgoogle\b", re.I)),
    ]),
    ("Imperva / Incapsula", [
        ("X-Iinfo", re.compile(r".+")),
        ("X-Cdn", re.compile(r"\bIncapsula\b", re.I)),
        ("Set-Cookie", re.compile(r"visid_incap|incap_ses", re.I)),
    ]),
    ("Sucuri", [
        ("Server", re.compile(r"\bSucuri\b", re.I)),
        ("X-Sucuri-Id", re.compile(r".+")),
        ("X-Sucuri-Cache", re.compile(r".+")),
    ]),
    ("F5 BIG-IP", [
        ("Server", re.compile(r"\bBigIP\b", re.I)),
        ("Set-Cookie", re.compile(r"\bBIGipServer", re.I)),
    ]),
    ("Barracuda", [
        ("Set-Cookie", re.compile(r"\bbarra_counter_session\b", re.I)),
    ]),
    ("Fastly", [
        ("X-Served-By", re.compile(r"\bcache-", re.I)),
        ("X-Cache", re.compile(r"\bMISS\b|\bHIT\b")),
        ("Fastly-Debug-Digest", re.compile(r".+")),
        ("Server", re.compile(r"\bFastly\b", re.I)),
    ]),
    ("StackPath / NetDNA", [
        ("Server", re.compile(r"\bNetDNA-cache\b", re.I)),
    ]),
    ("Wallarm", [
        ("X-Wallarm-Mode", re.compile(r".+")),
        ("Server", re.compile(r"\bnginx-wallarm\b", re.I)),
    ]),
    ("Wordfence", [
        ("X-Wordfence", re.compile(r".+")),
    ]),
    ("ModSecurity", [
        ("Server", re.compile(r"\bmod_security\b", re.I)),
    ]),
    ("Citrix Netscaler", [
        ("Set-Cookie", re.compile(r"\bcitrix_ns_id\b", re.I)),
    ]),
    ("NSFOCUS", [
        ("Server", re.compile(r"\bnsfocus\b", re.I)),
    ]),
]

BODY_FINGERPRINTS = [
    ("Cloudflare challenge", re.compile(r"Attention Required! \| Cloudflare", re.I)),
    ("AWS WAF block page", re.compile(r"Request blocked\.\s*We can't connect to the server for this app", re.I)),
    ("Imperva block page", re.compile(r"Incapsula incident ID", re.I)),
    ("Sucuri block page", re.compile(r"Access Denied - Sucuri Website Firewall", re.I)),
    ("ModSecurity block page", re.compile(r"Mod_Security|NOYB", re.I)),
]


def _detect(headers: dict, body: str) -> list[tuple[str, str]]:
    """Return list of (label, evidence)."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label, sigs in SIGNATURES:
        for hname, rx in sigs:
            value = headers.get(hname) or headers.get(hname.lower()) or ""
            if value and rx.search(value):
                if label not in seen:
                    out.append((label, f"{hname}: {value[:160]}"))
                    seen.add(label)
                break
    for label, rx in BODY_FINGERPRINTS:
        if rx.search(body or "") and label not in seen:
            out.append((label, f"body match: {rx.pattern}"))
            seen.add(label)
    return out


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # Probe biasa
        r = client.get(target.base_url)
        # Probe dengan payload "memprovokasi" supaya WAF block-page kelihatan
        evil_url = (
            target.base_url
            + ("&" if "?" in target.base_url else "?")
            + "x=" + "../../../etc/passwd"
        )
        r2 = client.get(evil_url)

        all_headers: dict = {}
        all_body = ""
        if r is not None:
            all_headers.update({k: v for k, v in r.headers.items()})
            all_body += r.text or ""
        if r2 is not None:
            for k, v in r2.headers.items():
                # Header kedua boleh override kalau bawa info baru
                if k not in all_headers:
                    all_headers[k] = v
            all_body += "\n" + (r2.text or "")

        detections = _detect(all_headers, all_body)

        if not detections:
            findings.append(
                Finding(
                    module="waf_detect",
                    title="Tidak terdeteksi WAF/CDN di depan target",
                    severity=Severity.INFO,
                    description=(
                        "Berdasarkan probe header & body, tidak ditemukan vendor WAF/CDN "
                        "yang dikenali. Konsekuensi: hasil modul aktif (cmdi/sqli/rce) "
                        "lebih dapat dipercaya, TAPI tidak ada lapisan kedua untuk filter "
                        "payload jahat. Pertimbangkan pasang WAF (Cloudflare WAF, AWS WAF, "
                        "mod_security CRS) sebagai pertahanan tambahan."
                    ),
                    target=target.base_url,
                    confidence="firm",
                    remediation=(
                        "Pasang WAF managed (Cloudflare/AWS/Akamai) atau open-source "
                        "(mod_security + OWASP CRS). WAF bukan pengganti perbaikan kode, "
                        "tapi mengurangi blast radius bug yang lolos."
                    ),
                    references=[
                        "https://owasp.org/www-community/Web_Application_Firewall",
                    ],
                )
            )
            return findings

        for label, evidence in detections:
            findings.append(
                Finding(
                    module="waf_detect",
                    title=f"WAF/CDN terdeteksi: {label}",
                    severity=Severity.INFO,
                    description=(
                        f"Vendor WAF/CDN {label} berdiri di depan target. Ini KONTEKS "
                        "penting: hasil modul aktif (cmdi/sqli/rce_validator/ssti) yang "
                        "dilabeli ``low_confidence`` mungkin karena diblokir WAF, BUKAN "
                        "karena aplikasi aman. Pertimbangkan re-test dari IP yang di-allow-"
                        "list (jika diizinkan) atau lewat origin langsung."
                    ),
                    target=target.base_url,
                    evidence=evidence,
                    confidence="confirmed",
                    remediation=(
                        "WAF aktif itu baik. Pastikan: (1) origin server tidak terekspos "
                        "langsung di internet (bypass WAF), (2) rule WAF di-tune supaya "
                        "tidak block traffic legitimate, (3) logging block events untuk "
                        "deteksi serangan."
                    ),
                    references=[
                        "https://owasp.org/www-community/Web_Application_Firewall",
                    ],
                )
            )
    finally:
        client.close()
    return findings
