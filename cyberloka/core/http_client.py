"""Rate-limited HTTP client wrapper around requests."""
from __future__ import annotations

import threading
import time
from typing import Any

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from cyberloka.core.config import ScanConfig

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
    """Thin wrapper over requests.Session with safe defaults.

    Bila `config.headers` memuat `Authorization` (mis. dari --auth-token),
    atau `config.cookies` memuat cookie hasil login form, maka semua request
    akan otomatis terotentikasi.
    """

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

    def request(
        self,
        method: str,
        url: str,
        *,
        allow_redirects: bool | None = None,
        **kwargs: Any,
    ) -> requests.Response | None:
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
