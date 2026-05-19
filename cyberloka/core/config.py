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
        "subdomain_takeover", "api_discovery", "email_security",
        "email_security_extended", "nextjs_specific", "cf_origin",
        "wayback", "framework_default", "graphql_deep", "source_leak",
        "cms_scan", "cloud_buckets", "k8s_exposure", "dependency_confusion",
        "favicon_hash",
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
        "deep_login_audit", "root_access_check",
        # 15 modul baru (web-dashboard, multi-signal validation)
        "wp_user_enum", "wp_xmlrpc", "wp_admin_default",
        "basic_auth_default", "swagger_walker", "prometheus_metrics_leak",
        "git_repo_dump", "tomcat_manager_default", "phpmyadmin_default",
        "adminer_exposed", "kibana_unauth", "grafana_default",
        "ftp_anonymous", "idor_active_chain", "websocket_auth_check",
        "balance", "env_leak", "api_auth", "mass_assignment",
        "log_injection", "jwt_confusion", "crlf_injection", "nosqli",
        "deserialization", "webhook_signature", "csv_injection",
        "graphql_dos", "xpath_injection", "logout_csrf", "zip_slip",
        "ldap_injection", "captcha_bypass", "xslt_injection",
        "rate_limit_bypass", "response_splitting", "timing_attack",
        "stored_xss", "url_preview_ssrf", "private_profile_bypass",
        "media_persistence", "dm_privacy", "social_csrf", "oauth_takeover",
        "unicode_bypass",
        # v0.10.0 — 30 modul critical/high baru (auto-validation).
        # adminer_exposed & kibana_unauth sudah ada di blok 15 modul atas.
        "apache_path_confusion", "phpunit_rce", "log4shell_probe",
        "spring_actuator_rce", "gitlab_unauth_api", "jenkins_unauth_console",
        "wp_xmlrpc_amplify", "drupalgeddon2", "bypass_403",
        "docker_remote_api", "elasticsearch_unauth", "prometheus_unauth",
        "grafana_default_login", "solr_admin_unauth",
        "phpmyadmin_exposed", "iis_shortname",
        "cache_deception", "cors_null_origin", "smtp_header_injection",
        "oauth_redirect_bypass", "s3_world_writable", "firebase_open_db",
        "csti_template", "api_version_downgrade", "grpc_reflection",
        "saml_metadata_exposed", "webdav_writable", "nginx_off_by_slash",
        # v0.10.1 — deep validation scanners
        "xss_deep", "login_bypass_deep", "curl_active_verify",
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
