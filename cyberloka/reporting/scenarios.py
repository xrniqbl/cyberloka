"""Adapter scenarios untuk per-finding di report.

File ini TIDAK menduplikasi `explainer.py` — ia menyatukan tiga sumber
yang sudah ada menjadi satu API tunggal `get_scenario(finding)` agar
konsumen (PDF/HTML/JSON reporter) tidak perlu meng-query banyak modul:

  1. explainer.EXPLAIN[module]   - friendly_name, what_it_means,
                                   business_impact (105 modul Anda)
  2. extras.OWASP_MAP[module]    - kategori OWASP Top 10 2021
  3. extras.MITRE_MAP[module]    - teknik MITRE ATT&CK
  4. extras.REPRO_MAP[module]    - perintah reproduksi manual
  5. pdf_report.ACCESS_GAINED_MAP - label akses yang tertembus

Pemakaian:

    from cyberloka.reporting.scenarios import get_scenario, is_access_gained

    sc = get_scenario(finding)
    print(sc["what"])      # apa celahnya
    print(sc["impact"])    # dampak bisnis
    print(sc["repro"])     # cara reproduksi
    print(sc["owasp"])     # OWASP category
    print(sc["mitre"])     # MITRE technique

    gained, label = is_access_gained(finding)
"""
from __future__ import annotations

from typing import Any

from cyberloka.core import Finding, Severity
from cyberloka.reporting.explainer import EXPLAIN
from cyberloka.reporting.extras import MITRE_MAP, OWASP_MAP, REPRO_MAP


def _safe_format(template: str, **kw: Any) -> str:
    """Format template `{url}/{host}` aman: kalau ada placeholder yang tidak
    di-supply atau tidak ada di template, jangan crash."""
    if not template:
        return ""
    try:
        return template.format(**kw)
    except (KeyError, IndexError, ValueError):
        return template


def get_scenario(
    finding: Finding | dict[str, Any],
    *,
    target_url: str = "",
    target_host: str = "",
) -> dict[str, str]:
    """Bangun scenario dict per finding (dipakai semua reporter).

    Args:
      finding:    `Finding` instance atau dict (hasil to_dict).
      target_url: URL utama target (untuk substitusi {url} di REPRO_MAP).
                  Biasanya `target.base_url` dari ScanConfig.
      target_host: Hostname target (untuk substitusi {host} di REPRO_MAP).

    Returns:
      Dict dengan keys: module, what, impact, owasp, mitre, repro,
      friendly_name, category. Nilai kosong pakai string kosong "".
    """
    if isinstance(finding, Finding):
        module = (finding.module or "").lower()
        finding_url = (finding.urls[0] if finding.urls else finding.target) or ""
    else:
        module = (finding.get("module") or "").lower()
        finding_url = (
            (finding.get("urls") or [None])[0]
            or finding.get("target")
            or ""
        )

    info = EXPLAIN.get(module, {})
    repro_template = REPRO_MAP.get(module, "")
    url = finding_url or target_url
    repro = _safe_format(repro_template, url=url, host=target_host)

    return {
        "module": module,
        "friendly_name": info.get("friendly_name", ""),
        "category": info.get("category", "lain"),
        "what": info.get("what_it_means", ""),
        "impact": info.get("business_impact", ""),
        "owasp": OWASP_MAP.get(module, ""),
        "mitre": MITRE_MAP.get(module, ""),
        "repro": repro,
    }


# ============================================================================
# Akses yang berhasil/dapat ditembus
# ============================================================================
# Single source of truth: di-import oleh pdf_report (untuk Bab 3 "Akses
# Yang Dapat / Berhasil Ditembus") dan oleh HTML report.
#
# Format: { module_name: (label, severity_threshold) }
#   threshold "any"  = severity apa pun memicu (mis. .git/.env exposed)
#   threshold "high" = hanya CRITICAL/HIGH yang memicu

ACCESS_GAINED_MAP: dict[str, tuple[str, str]] = {
    # File / source code / kredensial
    "sensitive_files": ("Source code / kredensial via file ter-ekspos", "any"),
    "source_leak": ("Source code internal bocor", "any"),
    "env_leak": ("Kredensial environment bocor", "any"),
    "api_key_in_url": ("API key bocor di URL/log", "any"),
    "sentry_dsn_leak": ("Sentry DSN bocor", "any"),
    # Database
    "sqli": ("Akses database (SQL Injection)", "any"),
    "nosqli": ("Akses NoSQL database", "any"),
    "xpath_injection": ("Pencurian data via XPath injection", "any"),
    "ldap_injection": ("Akses direktori LDAP", "any"),
    # RCE
    "cmdi": ("Remote Code Execution (Command Injection)", "any"),
    "ssti": ("Remote Code Execution (Template Injection)", "any"),
    "deserialization": ("Remote Code Execution (deserialization)", "any"),
    "file_upload": ("Webshell upload / RCE via file upload", "any"),
    "zip_slip": ("Penulisan file arbitrer (Zip Slip)", "any"),
    "proto_pollution": ("Prototype pollution / RCE chain", "any"),
    # Akses lateral
    "ssrf": ("Akses internal network (SSRF)", "high"),
    "ssrf_metadata": ("Akses cloud metadata (IAM credentials cloud)", "any"),
    "lfi": ("Pembacaan file server", "any"),
    "xxe": ("Pencurian data via XXE", "any"),
    "url_preview_ssrf": ("SSRF via URL preview", "any"),
    # Account takeover
    "host_header": ("Account takeover via password-reset hijack", "high"),
    "password_reset": ("Account takeover via password reset", "any"),
    "oauth_takeover": ("Account takeover via OAuth flow", "any"),
    "auth_bypass": ("Bypass autentikasi", "any"),
    "jwt": ("Forgery token JWT (impersonation)", "high"),
    "jwt_confusion": ("JWT algorithm confusion attack", "any"),
    "session": ("Pengambilalihan session", "high"),
    "logout_csrf": ("Forced logout / CSRF", "any"),
    "otp_check": ("Bypass OTP / 2FA", "any"),
    "captcha_bypass": ("Bypass captcha", "any"),
    # Akses data
    "idor_generic": ("Akses data user lain (IDOR)", "any"),
    "mass_assignment": ("Eskalasi privilege via mass assignment", "any"),
    "private_profile_bypass": ("Bypass private profile", "any"),
    "media_persistence": ("Akses media setelah dihapus", "any"),
    "pii_leak": ("Kebocoran data pribadi", "any"),
    "dm_privacy": ("Kebocoran direct message", "any"),
    # Money / fraud
    "voucher": ("Penyalahgunaan voucher", "any"),
    "payment": ("Manipulasi payment flow", "any"),
    "balance": ("Manipulasi saldo", "any"),
    "race_condition": ("Eksploitasi race condition", "any"),
    # Attacker control
    "subdomain_takeover": ("Subdomain takeover (full content control)", "any"),
    "cloud_buckets": ("Akses cloud storage publik", "any"),
    "cf_origin": ("Bypass CDN/WAF (akses origin langsung)", "any"),
    "k8s_exposure": ("Akses Kubernetes API", "any"),
    "dependency_confusion": ("Supply-chain takeover via dependency", "any"),
    # XSS / client side
    "xss": ("Eksekusi JS di browser korban (session theft)", "any"),
    "stored_xss": ("Stored XSS aktif", "any"),
    "dom_xss": ("DOM XSS aktif", "any"),
    "social_csrf": ("CSRF di alur social media", "any"),
    "csrf": ("Aksi sensitif via CSRF", "any"),
    # Misc
    "redirect": ("Phishing via domain target", "any"),
    "dirlist": ("Browsing folder server", "any"),
    "rate_limit": ("Brute-force / credential stuffing terbuka", "high"),
    "rate_limit_bypass": ("Bypass rate-limit", "any"),
    "captcha_check": ("Captcha lemah", "high"),
    "cors": ("Pembacaan API lintas-origin (data exfil)", "high"),
    "cors_advanced": ("Pembacaan API lintas-origin (advanced)", "high"),
    "cache_poison": ("Cache poisoning", "any"),
    "http_smuggling": ("HTTP request smuggling", "any"),
    "response_splitting": ("HTTP response splitting", "any"),
    "crlf_injection": ("CRLF injection", "any"),
    "log_injection": ("Log injection / forging", "any"),
    "csv_injection": ("CSV / formula injection", "any"),
    "rfd": ("Reflected file download", "any"),
    "webhook_signature": ("Webhook signature bypass", "any"),
    # Recon high-impact
    "api_discovery": ("Management console / dokumentasi API", "high"),
    "api_auth": ("API tanpa autentikasi", "high"),
    "graphql_deep": ("Schema GraphQL ter-ekspos", "high"),
    "graphql_dos": ("GraphQL DoS", "any"),
    # Info
    "exif_leak": ("Geo-location bocor di EXIF", "any"),
    "homoglyph_check": ("Risiko homograph phishing", "any"),

    # ============ DEEP SCANNERS (PR #9 + PR #10) ============
    # PR #9 - akses data / saldo / file / webhook / subdomain
    "db_exposure": ("Akses langsung ke database / data store", "any"),
    "saldo_deep": ("Manipulasi saldo & transaksi (mendalam)", "any"),
    "file_inject": ("Webshell / RCE via file upload (mendalam)", "any"),
    "webhook_deep": ("Forge transaksi pembayaran via webhook", "any"),
    "subdomain_access": ("Panel internal / subdomain dev terbuka", "high"),
    # PR #10 - active
    "shellshock": ("Remote Code Execution (Shellshock CVE-2014-6271)", "any"),
    "mfa_bypass": ("Bypass 2FA / MFA — pengambilalihan akun", "any"),
    # PR #10 - recon source-leak
    "git_disclosure": ("Source code lengkap via .git/ disclosure", "any"),
    "svn_disclosure": ("Source code lengkap via .svn/ disclosure", "any"),
    "iis_shortname": ("Penemuan file tersembunyi (IIS 8.3)", "any"),
    # PR #10 - CMS
    "wp_scan": ("Username & xmlrpc WordPress untuk brute-force", "high"),
    "joomla_scan": ("Re-install Joomla via /installation/", "high"),
    "drupal_scan": ("Versi Drupal exact + advisory yang berlaku", "high"),
    # PR #10 - infra
    "vhost_brute": ("Akses vhost internal via Host header", "any"),
    # PR #10 - data leak
    "hash_disclosure": ("Hash password / token bocor di response", "any"),
    "ds_store_leak": ("Listing file via .DS_Store leak", "any"),
}


def is_access_gained(finding: Finding | dict[str, Any]) -> tuple[bool, str]:
    """Return (gained, label) — apakah finding ini menandai akses tertembus.

    Threshold:
      - "any":  finding apa pun di modul ini = akses tertembus
      - "high": hanya kalau severity CRITICAL atau HIGH
    """
    if isinstance(finding, Finding):
        module = (finding.module or "").lower()
        sev = finding.severity
    else:
        module = (finding.get("module") or "").lower()
        sev_val = finding.get("severity", "info")
        try:
            sev = Severity(sev_val) if not isinstance(sev_val, Severity) else sev_val
        except ValueError:
            sev = Severity.INFO

    cfg = ACCESS_GAINED_MAP.get(module)
    if not cfg:
        return False, ""
    label, threshold = cfg
    if threshold == "any":
        return True, label
    if threshold == "high" and sev in (Severity.CRITICAL, Severity.HIGH):
        return True, label
    return False, ""
