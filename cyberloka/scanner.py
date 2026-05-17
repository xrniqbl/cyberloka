"""Scanner orchestrator: runs selected modules and aggregates findings."""
from __future__ import annotations

import importlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from cyberloka.core import Finding, Target, authenticate
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
    "crawler": "cyberloka.recon.crawler",
    "openapi": "cyberloka.recon.openapi",
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
    # active
    "sqli": "cyberloka.active.sqli",
    "xss": "cyberloka.active.xss",
    "redirect": "cyberloka.active.redirect",
    "lfi": "cyberloka.active.lfi",
    "cmdi": "cyberloka.active.cmdi",
    "dirlist": "cyberloka.active.dirlist",
    "ssrf": "cyberloka.active.ssrf",
    "jwt": "cyberloka.active.jwt_audit",
    "xxe": "cyberloka.active.xxe",
    "ssti": "cyberloka.active.ssti",
    "nosqli": "cyberloka.active.nosqli",
    "graphql": "cyberloka.active.graphql_audit",
    "websocket": "cyberloka.active.websocket",
    # simulate
    "rate_limit": "cyberloka.simulate.rate_limit",
    "burst": "cyberloka.simulate.burst",
}

# Modul-modul yang HARUS jalan sebelum modul lain (untuk menyiapkan state)
PREREQ_MODULES = ("crawler", "openapi")


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


def _do_auth(config: ScanConfig) -> tuple[bool, str]:
    """Lakukan auth dan suntikkan cookies/headers ke config supaya semua HttpClient memakainya."""
    log = get_logger()
    if config.auth.method == "none":
        return True, "no auth"
    sess = requests.Session()
    sess.headers.update({"User-Agent": config.user_agent})
    if config.headers:
        sess.headers.update(config.headers)
    if config.cookies:
        sess.cookies.update(config.cookies)
    if config.proxy:
        sess.proxies = {"http": config.proxy, "https": config.proxy}

    ok, msg = authenticate(sess, config.auth)
    if ok:
        # propagate hasil ke config supaya HttpClient di tiap modul ikut auth
        for k, v in sess.headers.items():
            config.headers[k] = v
        for c in sess.cookies:
            config.cookies[c.name] = c.value
        log.info("[green]Auth OK:[/green] %s", msg)
    else:
        log.error("[red]Auth gagal:[/red] %s", msg)
    sess.close()
    return ok, msg


def run_scan(target: Target, config: ScanConfig) -> list[Finding]:
    """Run all selected modules and return aggregated findings."""
    log = get_logger()

    # 1) Auth (jika diminta)
    if config.auth.method != "none":
        ok, msg = _do_auth(config)
        if not ok:
            log.warning(
                "Lanjut tanpa otentikasi (modul yang butuh login akan terbatas)."
            )

    modules = config.resolve_modules()
    if config.simulate_attack:
        modules = list(modules) + ["burst"]
        if config.login_url:
            modules.append("rate_limit")

    findings: list[Finding] = []

    # 2) Jalankan prerequisite modules dulu (mis. crawler) secara serial
    prereq = [m for m in modules if m in PREREQ_MODULES]
    rest = [m for m in modules if m not in PREREQ_MODULES]

    for m in prereq:
        findings.extend(_run_module(m, target, config))

    # 3) Sisanya boleh paralel — tiap modul self-contained dan rate-limited
    if rest:
        with ThreadPoolExecutor(max_workers=max(1, min(config.threads, len(rest)))) as ex:
            future_to_name = {ex.submit(_run_module, m, target, config): m for m in rest}
            for fut in as_completed(future_to_name):
                findings.extend(fut.result())
    return findings
