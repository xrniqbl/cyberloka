"""Scan configuration."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class LoginSession:
    """Authenticated session configuration for scans behind a login.

    Two ways to authenticate:

    * **form**: POST credentials to `url`, capture all cookies returned
      (default — works for most Django/Laravel/Rails-style logins).
    * **header**: send a static header on every request (e.g.
      `Authorization: Bearer <token>` or `Cookie: session=abc; csrf=xyz`).

    Optionally specify `success_indicator` (substring expected in the body
    on successful login) and `success_url_pattern` (regex on final URL) so
    the scanner can refuse to proceed if login appears to have failed.
    """

    method: str = "form"  # "form" | "header" | "cookie"
    url: str | None = None
    username: str | None = None
    password: str | None = None
    user_field: str = "username"
    pass_field: str = "password"
    extra_fields: dict[str, str] = field(default_factory=dict)
    success_indicator: str | None = None  # substring expected in success page body
    failure_indicator: str | None = None  # substring that signals failure
    success_url_pattern: str | None = None  # regex on final URL after login
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    csrf_url: str | None = None  # GET this first to grab CSRF token
    csrf_field: str | None = None  # name of <input name="..."> holding the token
    logout_url: str | None = None  # avoid hitting this URL during scan

    @classmethod
    def from_file(cls, path: str | Path) -> "LoginSession":
        """Load a login config from a JSON file.

        Example:
            {
              "method": "form",
              "url": "https://example.com/login",
              "username": "alice",
              "password": "secret",
              "success_indicator": "Welcome,",
              "csrf_url": "https://example.com/login",
              "csrf_field": "csrf_token"
            }
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**data)


@dataclass
class ScanConfig:
    target: str
    mode: str = "passive"  # passive | active | full
    modules: list[str] = field(default_factory=list)  # empty = use mode default
    threads: int = 10
    timeout: float = 10.0
    rate_limit: float = 10.0  # max req/s
    user_agent: str = (
        "Mozilla/5.0 (compatible; Cyberloka/0.1; +https://github.com/xrniqbl/cyberloka)"
    )
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    verify_tls: bool = True
    follow_redirects: bool = True
    max_redirects: int = 5
    authorized: bool = False
    simulate_attack: bool = False
    login_url: str | None = None
    login_user_field: str = "username"
    login_pass_field: str = "password"
    login_test_user: str = "admin"
    # New: full authenticated-session config (loaded from --login-config JSON
    # or built interactively from the menu).
    login_session: LoginSession | None = None
    quiet: bool = False
    json_out: str | None = None
    html_out: str | None = None
    txt_out: str | None = None
    pdf_out: str | None = None
    proxy: str | None = None

    PASSIVE_MODULES = (
        "headers",
        "tls",
        "cookies",
        "cors",
        "clickjacking",
        "methods",
        "sensitive_files",
        "fingerprint",
        "robots",
        "dns",
    )
    ACTIVE_MODULES = (
        "sqli",
        "xss",
        "redirect",
        "lfi",
        "cmdi",
        "dirlist",
    )
    RECON_MODULES = (
        "dns",
        "whois",
        "ports",
        "subdomains",
        "fingerprint",
    )

    def resolve_modules(self) -> list[str]:
        if self.modules:
            return list(self.modules)
        if self.mode == "passive":
            return list(self.PASSIVE_MODULES)
        if self.mode == "active":
            return list(self.PASSIVE_MODULES) + list(self.ACTIVE_MODULES)
        if self.mode == "full":
            mods = list(dict.fromkeys(
                list(self.RECON_MODULES)
                + list(self.PASSIVE_MODULES)
                + list(self.ACTIVE_MODULES)
            ))
            return mods
        raise ValueError(f"Unknown mode: {self.mode}")
