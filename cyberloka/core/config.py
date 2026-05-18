"""Scan configuration."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    target: str
    mode: str = "passive"  # passive | active | full
    modules: list[str] = field(default_factory=list)  # empty = use mode default
    threads: int = 10
    timeout: float = 10.0
    rate_limit: float = 10.0  # max req/s
    user_agent: str = (
        "Mozilla/5.0 (compatible; Cyberloka/0.2; +https://github.com/xrniqbl/cyberloka)"
    )
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    verify_tls: bool = True
    follow_redirects: bool = True
    max_redirects: int = 5
    max_crawl_pages: int = 30
    authorized: bool = False
    simulate_attack: bool = False
    login_url: str | None = None
    login_user_field: str = "username"
    login_pass_field: str = "password"
    login_test_user: str = "admin"
    quiet: bool = False
    json_out: str | None = None
    html_out: str | None = None
    proxy: str | None = None

    # ------------------------------------------------------------------
    # Module sets per mode.
    #
    # Recon dimasukkan ke "passive" agar laporan default selalu memuat
    # informasi DNS, WHOIS, port terbuka, fingerprint teknologi, dan API
    # discovery — yang sebelumnya hanya muncul di mode "full".
    # ------------------------------------------------------------------

    RECON_MODULES = (
        "dns",
        "whois",
        "ports",
        "fingerprint",
        "subdomains",
        "subdomain_takeover",
        "api_discovery",
    )
    PASSIVE_MODULES = (
        # Observasi non-intrusif (selalu aman dijalankan).
        "headers",
        "tls",
        "cookies",
        "cors",
        "clickjacking",
        "methods",
        "sensitive_files",
        "robots",
        "outdated_libs",
        "mixed_content",
        "jwt",
    )
    # Modul aktif (mengirim payload uji). Crawler dijalankan dulu agar
    # discovery state (URL, form, parameter) tersedia untuk modul lain.
    ACTIVE_MODULES = (
        "crawler",
        "csrf",
        "sqli",
        "xss",
        "redirect",
        "lfi",
        "cmdi",
        "dirlist",
        "ssrf",
        "ssti",
        "forms",
        "session",
        "voucher",
        "payment",
    )

    def resolve_modules(self) -> list[str]:
        if self.modules:
            return list(self.modules)
        if self.mode == "passive":
            # Recon + passive observation. Tetap aman (tanpa payload aktif).
            return list(dict.fromkeys(
                list(self.RECON_MODULES) + list(self.PASSIVE_MODULES)
            ))
        if self.mode == "active":
            return list(dict.fromkeys(
                list(self.RECON_MODULES)
                + list(self.PASSIVE_MODULES)
                + list(self.ACTIVE_MODULES)
            ))
        if self.mode == "full":
            return list(dict.fromkeys(
                list(self.RECON_MODULES)
                + list(self.PASSIVE_MODULES)
                + list(self.ACTIVE_MODULES)
            ))
        raise ValueError(f"Unknown mode: {self.mode}")
