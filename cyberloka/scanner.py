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
    # recon
    "dns": "cyberloka.recon.dns_recon",
    "whois": "cyberloka.recon.whois_recon",
    "ports": "cyberloka.recon.ports",
    "subdomains": "cyberloka.recon.subdomains",
    "subdomain_takeover": "cyberloka.recon.subdomain_takeover",
    "fingerprint": "cyberloka.recon.fingerprint",
    "api_discovery": "cyberloka.recon.api_discovery",
    "crawler": "cyberloka.recon.crawler",
    "email_security": "cyberloka.recon.email_security",
    "nextjs_specific": "cyberloka.recon.nextjs_specific",
    "cf_origin": "cyberloka.recon.cf_origin",
    "wayback": "cyberloka.recon.wayback",
    "framework_default": "cyberloka.recon.framework_default",
    "graphql_deep": "cyberloka.recon.graphql_deep",
    "source_leak": "cyberloka.recon.source_leak",
    # passive
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
    # active
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
    # simulate
    "rate_limit": "cyberloka.simulate.rate_limit",
    "burst": "cyberloka.simulate.burst",
}

# Modules that must run before others (e.g. crawler populates shared state).
PREREQ_MODULES: tuple[str, ...] = ("crawler",)


def _run_module(name: str, target: Target, config: ScanConfig) -> list[Finding]:
    log = get_logger()
    if name not in MODULE_MAP:
        log.warning("Modul tidak dikenal: %s", name)
        return []
    try:
        mod = importlib.import_module(MODULE_MAP[name])
    except Exception as e:  # noqa: BLE001
        log.error("Gagal import modul %s: %s", name, e)
        return []
    try:
        log.info("[bold]Running module:[/bold] %s", name)
        t0 = time.monotonic()
        findings = mod.run(target, config) or []
        dt = time.monotonic() - t0
        log.info("  -> %s: %d finding (%.2fs)", name, len(findings), dt)
        return findings
    except Exception as e:  # noqa: BLE001
        log.exception("Error in module %s: %s", name, e)
        return []


def run_scan(
    target: Target,
    config: ScanConfig,
    progress_cb=None,
) -> list[Finding]:
    """Run all selected modules and return aggregated findings.

    progress_cb(name, done, total) is invoked after each module completes.
    """
    log = get_logger()
    # Authenticated scan: try login once before crawling.
    if config.login_username or config.auth_bearer_token:
        try:
            ok = perform_login(config)
            log.info("[auth] result=%s", ok)
        except Exception as e:  # noqa: BLE001
            log.warning("[auth] login error: %s", e)

    modules = list(config.resolve_modules())
    if config.simulate_attack:
        modules.append("burst")
        if config.login_url:
            modules.append("rate_limit")

    findings: list[Finding] = []
    total = len(modules)
    done = 0

    # Run prereqs sequentially so their state is available downstream.
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
    return findings
