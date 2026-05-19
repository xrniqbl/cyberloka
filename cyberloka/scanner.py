"""Scanner orchestrator: runs selected modules and aggregates findings."""
from __future__ import annotations

import importlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from cyberloka.core import Finding, Target
from cyberloka.core.auth import perform_login
from cyberloka.core.config import ScanConfig
from cyberloka.core.logger import get_logger

# Module name -> dotted import path
MODULE_MAP: dict[str, str] = {
    # ===== RECON =====
    "dns": "cyberloka.recon.dns_recon",
    "whois": "cyberloka.recon.whois_recon",
    "ports": "cyberloka.recon.ports",
    "subdomains": "cyberloka.recon.subdomains",
    "subdomain_takeover": "cyberloka.recon.subdomain_takeover",
    "fingerprint": "cyberloka.recon.fingerprint",
    "api_discovery": "cyberloka.recon.api_discovery",
    "crawler": "cyberloka.recon.crawler",
    "email_security": "cyberloka.recon.email_security",
    "email_security_extended": "cyberloka.recon.email_security_extended",
    "nextjs_specific": "cyberloka.recon.nextjs_specific",
    "cf_origin": "cyberloka.recon.cf_origin",
    "wayback": "cyberloka.recon.wayback",
    "framework_default": "cyberloka.recon.framework_default",
    "graphql_deep": "cyberloka.recon.graphql_deep",
    "source_leak": "cyberloka.recon.source_leak",
    "cms_scan": "cyberloka.recon.cms_scan",
    "cloud_buckets": "cyberloka.recon.cloud_buckets",
    "k8s_exposure": "cyberloka.recon.k8s_exposure",
    "dependency_confusion": "cyberloka.recon.dependency_confusion",
    "favicon_hash": "cyberloka.recon.favicon_hash",
    # ===== PASSIVE =====
    "headers": "cyberloka.passive.headers",
    "tls": "cyberloka.passive.tls_check",
    "cookies": "cyberloka.passive.cookies",
    "cors": "cyberloka.passive.cors",
    "clickjacking": "cyberloka.passive.clickjacking",
    "methods": "cyberloka.passive.methods",
    "sensitive_files": "cyberloka.passive.sensitive_files",
    "robots": "cyberloka.passive.robots",
    "csrf": "cyberloka.passive.csrf",
    "jwt": "cyberloka.passive.jwt_check",
    "outdated_libs": "cyberloka.passive.outdated_libs",
    "mixed_content": "cyberloka.passive.mixed_content",
    "csp_evaluator": "cyberloka.passive.csp_evaluator",
    "captcha_check": "cyberloka.passive.captcha_check",
    "cache_control_audit": "cyberloka.passive.cache_control_audit",
    "cors_advanced": "cyberloka.passive.cors_advanced",
    "cookie_scope": "cyberloka.passive.cookie_scope",
    "sentry_dsn_leak": "cyberloka.passive.sentry_dsn_leak",
    "server_timing_header": "cyberloka.passive.server_timing_header",
    "api_key_in_url": "cyberloka.passive.api_key_in_url",
    "autocomplete_audit": "cyberloka.passive.autocomplete_audit",
    # ===== ACTIVE =====
    "sqli": "cyberloka.active.sqli",
    "xss": "cyberloka.active.xss",
    "redirect": "cyberloka.active.redirect",
    "lfi": "cyberloka.active.lfi",
    "cmdi": "cyberloka.active.cmdi",
    "dirlist": "cyberloka.active.dirlist",
    "ssrf": "cyberloka.active.ssrf",
    "ssrf_metadata": "cyberloka.active.ssrf_metadata",
    "ssti": "cyberloka.active.ssti",
    "xxe": "cyberloka.active.xxe",
    "forms": "cyberloka.active.forms",
    "session": "cyberloka.active.session",
    "voucher": "cyberloka.active.voucher",
    "payment": "cyberloka.active.payment",
    "otp_check": "cyberloka.active.otp_check",
    "password_reset": "cyberloka.active.password_reset",
    "file_upload": "cyberloka.active.file_upload",
    "idor_generic": "cyberloka.active.idor_generic",
    "host_header": "cyberloka.active.host_header",
    "cache_poison": "cyberloka.active.cache_poison",
    "hpp": "cyberloka.active.hpp",
    "rfd": "cyberloka.active.rfd",
    "dom_xss": "cyberloka.active.dom_xss",
    "oauth_check": "cyberloka.active.oauth_check",
    "pii_leak": "cyberloka.active.pii_leak",
    "race_condition": "cyberloka.active.race_condition",
    "proto_pollution": "cyberloka.active.proto_pollution",
    "http_smuggling": "cyberloka.active.http_smuggling",
    "ws_check": "cyberloka.active.ws_check",
    "auth_bypass": "cyberloka.active.auth_bypass",
    "deep_login_audit": "cyberloka.active.deep_login_audit",
    "root_access_check": "cyberloka.active.root_access_check",
    "balance": "cyberloka.active.balance",
    "env_leak": "cyberloka.active.env_leak",
    "api_auth": "cyberloka.active.api_auth",
    "mass_assignment": "cyberloka.active.mass_assignment",
    "log_injection": "cyberloka.active.log_injection",
    "jwt_confusion": "cyberloka.active.jwt_confusion",
    "crlf_injection": "cyberloka.active.crlf_injection",
    "nosqli": "cyberloka.active.nosqli",
    "deserialization": "cyberloka.active.deserialization",
    "webhook_signature": "cyberloka.active.webhook_signature",
    "csv_injection": "cyberloka.active.csv_injection",
    "graphql_dos": "cyberloka.active.graphql_dos",
    "xpath_injection": "cyberloka.active.xpath_injection",
    "logout_csrf": "cyberloka.active.logout_csrf",
    "zip_slip": "cyberloka.active.zip_slip",
    "ldap_injection": "cyberloka.active.ldap_injection",
    "captcha_bypass": "cyberloka.active.captcha_bypass",
    "xslt_injection": "cyberloka.active.xslt_injection",
    "rate_limit_bypass": "cyberloka.active.rate_limit_bypass",
    "response_splitting": "cyberloka.active.response_splitting",
    "timing_attack": "cyberloka.active.timing_attack",
    # ===== SOSMED-SPECIFIC =====
    "stored_xss": "cyberloka.active.stored_xss",
    "url_preview_ssrf": "cyberloka.active.url_preview_ssrf",
    "private_profile_bypass": "cyberloka.active.private_profile_bypass",
    "media_persistence": "cyberloka.active.media_persistence",
    "exif_leak": "cyberloka.passive.exif_leak",
    "homoglyph_check": "cyberloka.passive.homoglyph_check",
    "dm_privacy": "cyberloka.active.dm_privacy",
    "social_csrf": "cyberloka.active.social_csrf",
    "oauth_takeover": "cyberloka.active.oauth_takeover",
    "unicode_bypass": "cyberloka.active.unicode_bypass",
    # ===== SIMULATE =====
    "rate_limit": "cyberloka.simulate.rate_limit",
    "burst": "cyberloka.simulate.burst",
}

PREREQ_MODULES: tuple[str, ...] = ("crawler",)


def _run_module(name: str, target: Target, config: ScanConfig) -> list[Finding]:
    log = get_logger()
    if name not in MODULE_MAP:
        log.warning("Modul tidak dikenal: %s", name)
        return []
    try:
        mod = importlib.import_module(MODULE_MAP[name])
    except Exception as e:
        log.error("Gagal import modul %s: %s", name, e)
        return []
    try:
        log.info("[bold]Running module:[/bold] %s", name)
        t0 = time.monotonic()
        findings = mod.run(target, config) or []
        dt = time.monotonic() - t0
        log.info("  -> %s: %d finding (%.2fs)", name, len(findings), dt)
        return findings
    except Exception as e:
        log.exception("Error in module %s: %s", name, e)
        return []


def run_scan(target: Target, config: ScanConfig, progress_cb=None) -> list[Finding]:
    log = get_logger()
    if config.login_username or config.auth_bearer_token:
        try:
            ok = perform_login(config)
            log.info("[auth] result=%s", ok)
        except Exception as e:
            log.warning("[auth] login error: %s", e)

    modules = list(config.resolve_modules())
    if config.simulate_attack:
        modules.append("burst")
        if config.login_url:
            modules.append("rate_limit")

    findings: list[Finding] = []
    total = len(modules)
    done = 0

    prereqs = [m for m in PREREQ_MODULES if m in modules]
    rest = [m for m in modules if m not in prereqs]

    for name in prereqs:
        findings.extend(_run_module(name, target, config))
        done += 1
        if progress_cb:
            progress_cb(name, done, total)

    if rest:
        with ThreadPoolExecutor(max_workers=max(1, min(config.threads, len(rest)))) as ex:
            future_to_name = {ex.submit(_run_module, m, target, config): m for m in rest}
            for fut in as_completed(future_to_name):
                findings.extend(fut.result())
                done += 1
                if progress_cb:
                    progress_cb(future_to_name[fut], done, total)
    return _enrich_findings(findings, target)


def _enrich_findings(findings: list[Finding], target: Target) -> list[Finding]:
    """Auto-fill Finding.urls dari target bila modul tidak meng-set sendiri.

    Ini membuat semua report (PDF/HTML) bisa menampilkan link bug clickable
    tanpa modul perlu di-update satu per satu. Kalau target sudah berupa URL,
    pakai langsung. Kalau hanya host/path, fall back ke base_url target.
    """
    for f in findings:
        if not f.urls:
            t = (f.target or "").strip()
            if t.startswith(("http://", "https://")):
                f.urls = [t]
            elif t and target.base_url:
                f.urls = [target.base_url]
    return findings
