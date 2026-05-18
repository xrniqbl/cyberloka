"""Scanner orchestrator: runs selected modules and aggregates findings."""
from __future__ import annotations

import importlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from cyberloka.core import Finding, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.logger import get_logger

# Module name -> dotted import path
MODULE_MAP: dict[str, str] = {
    # recon
    "dns": "cyberloka.recon.dns_recon",
    "whois": "cyberloka.recon.whois_recon",
    "ports": "cyberloka.recon.ports",
    "subdomains": "cyberloka.recon.subdomains",
    "fingerprint": "cyberloka.recon.fingerprint",
    "waf_detect": "cyberloka.recon.waf_detect",
    "subdomain_takeover": "cyberloka.recon.subdomain_takeover",
    # passive
    "headers": "cyberloka.passive.headers",
    "tls": "cyberloka.passive.tls_check",
    "cookies": "cyberloka.passive.cookies",
    "cors": "cyberloka.passive.cors",
    "clickjacking": "cyberloka.passive.clickjacking",
    "methods": "cyberloka.passive.methods",
    "sensitive_files": "cyberloka.passive.sensitive_files",
    "robots": "cyberloka.passive.robots",
    "api_discovery": "cyberloka.passive.api_discovery",
    "graphql": "cyberloka.passive.graphql",
    "csrf": "cyberloka.passive.csrf",
    "jwt": "cyberloka.passive.jwt_audit",
    "secrets": "cyberloka.passive.secrets",
    "mixed_content": "cyberloka.passive.mixed_content",
    "info_disclosure": "cyberloka.passive.info_disclosure",
    "cache": "cyberloka.passive.cache",
    # active
    "sqli": "cyberloka.active.sqli",
    "xss": "cyberloka.active.xss",
    "redirect": "cyberloka.active.redirect",
    "lfi": "cyberloka.active.lfi",
    "cmdi": "cyberloka.active.cmdi",
    "dirlist": "cyberloka.active.dirlist",
    "host_header": "cyberloka.active.host_header",
    "ssrf": "cyberloka.active.ssrf",
    # simulate
    "rate_limit": "cyberloka.simulate.rate_limit",
    "burst": "cyberloka.simulate.burst",
}


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


def run_scan(target: Target, config: ScanConfig) -> list[Finding]:
    """Run all selected modules and return aggregated findings."""
    modules = config.resolve_modules()
    if config.simulate_attack:
        modules = list(modules) + ["burst"]
        if config.login_url:
            modules.append("rate_limit")

    findings: list[Finding] = []
    # Run modules concurrently for speed; each module is itself thread-safe
    with ThreadPoolExecutor(max_workers=max(1, min(config.threads, len(modules)))) as ex:
        future_to_name = {ex.submit(_run_module, m, target, config): m for m in modules}
        for fut in as_completed(future_to_name):
            findings.extend(fut.result())
    return findings
