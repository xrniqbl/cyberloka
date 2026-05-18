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
        "Mozilla/5.0 (compatible; Cyberloka/0.3; +https://github.com/xrniqbl/cyberloka)"
    )
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    verify_tls: bool = True
    follow_redirects: bool = True
    max_redirects: int = 5
    max_crawl_pages: int = 30
    authorized: bool = False
    simulate_attack: bool = False

    # Existing rate-limit/login probe target.
    login_url: str | None = None
    login_user_field: str = "username"
    login_pass_field: str = "password"
    login_test_user: str = "admin"

    # Authenticated scan: if username/password OR bearer token present, the
    # runner will log in once and propagate the session cookie / Authorization
    # header to all modules.
    login_username: str | None = None
    login_password: str | None = None
    auth_bearer_token: str | None = None

    quiet: bool = False
    json_out: str | None = None
    html_out: str | None = None
    proxy: str | None = None

    # ------------------------------------------------------------------
    # Module sets per mode.
    #
    # Recon dimasukkan ke "passive" agar laporan default selalu memuat
    # informasi DNS, WHOIS, port terbuka, fingerprint, dll.
    # ------------------------------------------------------------------

    RECON_MODULES = (
        "dns",
        "whois",
        "ports",
        "fingerprint",
        "subdomains",
        "subdomain_takeover",
        "api_discovery",
        "email_security",
        "nextjs_specific",
        "cf_origin",
        "wayback",
        "framework_default",
        "graphql_deep",
        "source_leak",
    )
    PASSIVE_MODULES = (
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
        "csp_evaluator",
        "captcha_check",
    )
    ACTIVE_MODULES = (
        # Crawler dijalankan dulu agar discovery state (URL, form, parameter)
        # tersedia untuk modul lain.
        "crawler",
        "csrf",
        "sqli",
        "xss",
        "redirect",
        "lfi",
        "cmdi",
        "dirlist",
        "ssrf",
        "ssrf_metadata",
        "ssti",
        "xxe",
        "forms",
        "session",
        "voucher",
        "payment",
        "otp_check",
        "password_reset",
        "file_upload",
        "idor_generic",
        "host_header",
        "cache_poison",
        "hpp",
        "rfd",
        "dom_xss",
        "oauth_check",
        "pii_leak",
        "race_condition",
        "proto_pollution",
        "http_smuggling",
        "ws_check",
    )

    def resolve_modules(self) -> list[str]:
        if self.modules:
            return list(self.modules)
        if self.mode == "passive":
            return list(dict.fromkeys(
                list(self.RECON_MODULES) + list(self.PASSIVE_MODULES)
            ))
        if self.mode in ("active", "full"):
            return list(dict.fromkeys(
                list(self.RECON_MODULES)
                + list(self.PASSIVE_MODULES)
                + list(self.ACTIVE_MODULES)
            ))
        raise ValueError(f"Unknown mode: {self.mode}")
