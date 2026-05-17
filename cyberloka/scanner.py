"""Scanner orchestrator: runs selected modules and aggregates findings."""
from __future__ import annotations

import importlib
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from cyberloka.core import Finding, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.logger import get_logger

# Per-module execution stats (status: ok/error/skipped, count, duration_ms).
# Populated by run_scan() and exposed via run_scan() return + module_stats.
# Thread-safe via _stats_lock.
_stats_lock = threading.Lock()
_last_module_stats: list[dict] = []


def get_last_module_stats() -> list[dict]:
    """Return per-module execution stats from the most recent run_scan() call."""
    with _stats_lock:
        return list(_last_module_stats)


# Module name -> dotted import path
MODULE_MAP: dict[str, str] = {
    # recon
    "dns": "cyberloka.recon.dns_recon",
    "whois": "cyberloka.recon.whois_recon",
    "ports": "cyberloka.recon.ports",
    "subdomains": "cyberloka.recon.subdomains",
    "fingerprint": "cyberloka.recon.fingerprint",
    # passive
    "headers": "cyberloka.passive.headers",
    "tls": "cyberloka.passive.tls_check",
    "cookies": "cyberloka.passive.cookies",
    "cors": "cyberloka.passive.cors",
    "clickjacking": "cyberloka.passive.clickjacking",
    "methods": "cyberloka.passive.methods",
    "sensitive_files": "cyberloka.passive.sensitive_files",
    "robots": "cyberloka.passive.robots",
    # active
    "sqli": "cyberloka.active.sqli",
    "xss": "cyberloka.active.xss",
    "redirect": "cyberloka.active.redirect",
    "lfi": "cyberloka.active.lfi",
    "cmdi": "cyberloka.active.cmdi",
    "dirlist": "cyberloka.active.dirlist",
    # simulate
    "rate_limit": "cyberloka.simulate.rate_limit",
    "burst": "cyberloka.simulate.burst",
}


def _run_module(name: str, target: Target, config: ScanConfig) -> tuple[list[Finding], dict]:
    """Return (findings, stats) — stats has status/count/duration/error."""
    log = get_logger()
    stat = {"module": name, "status": "ok", "findings": 0, "duration_ms": 0, "error": None}
    if name not in MODULE_MAP:
        log.warning("Modul tidak dikenal: %s", name)
        stat["status"] = "skipped"
        stat["error"] = "module not in MODULE_MAP"
        return [], stat
    try:
        mod = importlib.import_module(MODULE_MAP[name])
    except Exception as e:  # noqa: BLE001
        log.error("Gagal import modul %s: %s", name, e)
        stat["status"] = "error"
        stat["error"] = f"import failed: {e}"
        return [], stat
    try:
        log.info("[bold]Running module:[/bold] %s", name)
        t0 = time.monotonic()
        findings = mod.run(target, config) or []
        dt = time.monotonic() - t0
        stat["findings"] = len(findings)
        stat["duration_ms"] = int(dt * 1000)
        log.info("  -> %s: %d finding (%.2fs)", name, len(findings), dt)
        return findings, stat
    except Exception as e:  # noqa: BLE001
        log.exception("Error in module %s: %s", name, e)
        stat["status"] = "error"
        stat["error"] = str(e)
        return [], stat


def run_scan(target: Target, config: ScanConfig) -> list[Finding]:
    """Run all selected modules and return aggregated findings.

    Per-module execution stats can be retrieved via `get_last_module_stats()`
    after this returns — useful for showing the user 'module X ran but
    found nothing' vs 'module Y was skipped'.
    """
    modules = config.resolve_modules()
    if config.simulate_attack:
        modules = list(modules) + ["burst"]
        if config.login_url:
            modules.append("rate_limit")

    findings: list[Finding] = []
    stats: list[dict] = []
    # Run modules concurrently for speed; each module is itself thread-safe.
    with ThreadPoolExecutor(max_workers=max(1, min(config.threads, len(modules)))) as ex:
        future_to_name = {ex.submit(_run_module, m, target, config): m for m in modules}
        for fut in as_completed(future_to_name):
            mod_findings, stat = fut.result()
            findings.extend(mod_findings)
            stats.append(stat)

    # Sort stats by module name for stable output
    stats.sort(key=lambda s: s["module"])
    with _stats_lock:
        _last_module_stats.clear()
        _last_module_stats.extend(stats)
    return findings
