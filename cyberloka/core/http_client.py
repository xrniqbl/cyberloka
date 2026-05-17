"""Rate-limited HTTP client wrapper around requests."""
from __future__ import annotations

import re
import threading
import time
from typing import Any

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from cyberloka.core.config import LoginSession, ScanConfig
from cyberloka.core.logger import get_logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class LoginError(RuntimeError):
    """Raised when an authenticated session could not be established."""


class RateLimiter:
    """Simple token-bucket-ish limiter."""

    def __init__(self, rate_per_sec: float):
        self.min_interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.monotonic()


class HttpClient:
    """Thin wrapper over requests.Session with safe defaults."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.limiter = RateLimiter(config.rate_limit)
        self.session = requests.Session()
        retry = Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS", "POST"]),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({"User-Agent": config.user_agent})
        if config.headers:
            self.session.headers.update(config.headers)
        if config.cookies:
            self.session.cookies.update(config.cookies)
        if config.proxy:
            self.session.proxies = {"http": config.proxy, "https": config.proxy}

        # Authenticated session establishment (best-effort; raises LoginError
        # on hard failure so the caller can decide whether to abort).
        self.authenticated = False
        if config.login_session is not None:
            self._establish_login(config.login_session)

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    def _establish_login(self, sess: LoginSession) -> None:
        log = get_logger()
        method = (sess.method or "form").lower()

        # 1) Header-only auth (e.g. Bearer token) -> just set headers and call it done.
        if method == "header":
            if not sess.headers:
                raise LoginError("login method=header requires `headers`")
            self.session.headers.update(sess.headers)
            self.authenticated = True
            log.info("[bold green]Login session: header-based auth applied[/bold green]")
            return

        # 2) Pre-set cookies (already-known session id from browser export).
        if method == "cookie":
            if not sess.cookies:
                raise LoginError("login method=cookie requires `cookies`")
            self.session.cookies.update(sess.cookies)
            if sess.headers:
                self.session.headers.update(sess.headers)
            self.authenticated = True
            log.info("[bold green]Login session: cookie-based auth applied[/bold green]")
            return

        # 3) Default: form-based login.
        if method != "form":
            raise LoginError(f"unknown login method: {method!r}")
        if not (sess.url and sess.username and sess.password):
            raise LoginError("login method=form requires url, username, and password")

        # Optional: pre-fetch CSRF token.
        data: dict[str, str] = {
            sess.user_field: sess.username,
            sess.pass_field: sess.password,
        }
        if sess.extra_fields:
            data.update(sess.extra_fields)

        if sess.csrf_url and sess.csrf_field:
            log.info("Fetching CSRF token from %s", sess.csrf_url)
            r = self.session.get(
                sess.csrf_url, timeout=self.config.timeout, verify=self.config.verify_tls
            )
            if r is not None and r.text:
                # Look for a hidden input or a meta tag carrying the token.
                m = re.search(
                    rf'name=["\']{re.escape(sess.csrf_field)}["\']\s+value=["\']([^"\']+)["\']',
                    r.text,
                ) or re.search(
                    rf'<meta[^>]+name=["\']{re.escape(sess.csrf_field)}["\'][^>]+content=["\']([^"\']+)["\']',
                    r.text,
                )
                if m:
                    data[sess.csrf_field] = m.group(1)
                    log.info("CSRF token captured")
                else:
                    log.warning("CSRF field %r not found on %s", sess.csrf_field, sess.csrf_url)

        if sess.headers:
            self.session.headers.update(sess.headers)

        log.info("[bold]Logging in:[/bold] POST %s as user=%r", sess.url, sess.username)
        try:
            resp = self.session.post(
                sess.url,
                data=data,
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
                allow_redirects=True,
            )
        except requests.RequestException as e:
            raise LoginError(f"login request failed: {e}") from e

        if resp is None:
            raise LoginError("login request returned no response")

        body = resp.text or ""
        final_url = resp.url or ""

        if sess.failure_indicator and sess.failure_indicator in body:
            raise LoginError(
                f"login appears to have failed (failure indicator '{sess.failure_indicator}' in body)"
            )
        if sess.success_indicator and sess.success_indicator not in body:
            raise LoginError(
                f"login appears to have failed (success indicator '{sess.success_indicator}' missing)"
            )
        if sess.success_url_pattern:
            if not re.search(sess.success_url_pattern, final_url):
                raise LoginError(
                    f"login appears to have failed (final URL {final_url!r} did not match "
                    f"pattern {sess.success_url_pattern!r})"
                )

        # As a soft check, ensure at least one cookie was set.
        if not self.session.cookies and not (sess.success_indicator or sess.success_url_pattern):
            log.warning(
                "Login POST returned status %s but no cookies were set. "
                "If your app uses tokens or different storage, set success_indicator "
                "or success_url_pattern in login config.",
                resp.status_code,
            )

        self.authenticated = True
        log.info(
            "[bold green]Login session established[/bold green] (status %s, %d cookies)",
            resp.status_code,
            len(self.session.cookies),
        )

    # ------------------------------------------------------------------
    # Request facade
    # ------------------------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        *,
        allow_redirects: bool | None = None,
        **kwargs: Any,
    ) -> requests.Response | None:
        # Don't accidentally hit logout URLs while scanning.
        sess = self.config.login_session
        if sess and sess.logout_url and url.rstrip("/") == sess.logout_url.rstrip("/"):
            return None
        self.limiter.wait()
        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
                allow_redirects=(
                    self.config.follow_redirects
                    if allow_redirects is None
                    else allow_redirects
                ),
                **kwargs,
            )
            return resp
        except requests.RequestException:
            return None

    def get(self, url: str, **kw: Any) -> requests.Response | None:
        return self.request("GET", url, **kw)

    def head(self, url: str, **kw: Any) -> requests.Response | None:
        return self.request("HEAD", url, **kw)

    def post(self, url: str, **kw: Any) -> requests.Response | None:
        return self.request("POST", url, **kw)

    def options(self, url: str, **kw: Any) -> requests.Response | None:
        return self.request("OPTIONS", url, **kw)

    def close(self) -> None:
        self.session.close()
