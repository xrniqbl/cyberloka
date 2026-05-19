"""Scan configuration."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    target: str
    mode: str = "passive"
    modules: list[str] = field(default_factory=list)
    threads: int = 10
    timeout: float = 10.0
    rate_limit: float = 10.0
    user_agent: str = (
        "Mozilla/5.0 (compatible; Cyberloka/0.8; +https://github.com/xrniqbl/cyberloka)"
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
    login_username: str | None = None
    login_password: str | None = None
    auth_bearer_token: str | None = None
    quiet: bool = False
    json_out: str | None = None
    html_out: str | None = None
    proxy: str | None = None

    RECON_MODULES = (
        "dns", "whois", "ports", "fingerprint", "subdomains",
        "subdomain_takeover", "subdomain_access", "api_discovery",
        "email_security", "email_security_extended", "nextjs_specific",
        "cf_origin", "wayback", "framework_default", "graphql_deep",
        "source_leak", "cms_scan", "cloud_buckets", "k8s_exposure",
        "dependency_confusion", "favicon_hash",
    )
    PASSIVE_MODULES = (
        "headers", "tls", "cookies", "cors", "clickjacking", "methods",
        "sensitive_files", "robots", "outdated_libs", "mixed_content", "jwt",
        "csp_evaluator", "captcha_check", "cache_control_audit",
        "cors_advanced", "cookie_scope", "sentry_dsn_leak",
        "server_timing_header", "api_key_in_url", "autocomplete_audit",
        "exif_leak", "homoglyph_check",
    )
    ACTIVE_MODULES = (
        "crawler", "csrf", "sqli", "xss", "redirect", "lfi", "cmdi",
        "dirlist", "ssrf", "ssrf_metadata", "ssti", "xxe", "forms",
        "session", "voucher", "payment", "otp_check", "password_reset",
        "file_upload", "idor_generic", "host_header", "cache_poison",
        "hpp", "rfd", "dom_xss", "oauth_check", "pii_leak", "race_condition",
        "proto_pollution", "http_smuggling", "ws_check", "auth_bypass",
        "balance", "saldo_deep", "env_leak", "db_exposure", "file_inject",
        "webhook_deep", "api_auth", "mass_assignment",
        "log_injection", "jwt_confusion", "crlf_injection", "nosqli",
        "deserialization", "webhook_signature", "csv_injection",
        "graphql_dos", "xpath_injection", "logout_csrf", "zip_slip",
        "ldap_injection", "captcha_bypass", "xslt_injection",
        "rate_limit_bypass", "response_splitting", "timing_attack",
        "stored_xss", "url_preview_ssrf", "private_profile_bypass",
        "media_persistence", "dm_privacy", "social_csrf", "oauth_takeover",
        "unicode_bypass",
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
