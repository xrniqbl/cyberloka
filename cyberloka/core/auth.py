"""Authenticated scan helper.

If the user provides login credentials in ScanConfig, log in *once* before
the scan starts and propagate the session cookies to every module via
config.cookies / config.headers. All modules use HttpClient, which loads
cookies/headers from config — so this gives instant authenticated coverage.
"""
from __future__ import annotations

from cyberloka.core.config import ScanConfig
from cyberloka.core.http_client import HttpClient
from cyberloka.core.logger import get_logger


def perform_login(config: ScanConfig) -> bool:
    """Try to authenticate. Returns True if a session cookie was captured."""
    log = get_logger()
    if config.auth_bearer_token:
        config.headers.setdefault("Authorization", f"Bearer {config.auth_bearer_token}")
        log.info("[auth] Bearer token applied to global headers.")
        return True

    if not (config.login_url and config.login_username and config.login_password):
        return False

    client = HttpClient(config)
    try:
        data = {
            config.login_user_field: config.login_username,
            config.login_pass_field: config.login_password,
        }
        # Allow extra hidden fields (mis. csrf token) — coba GET dulu, parse hidden.
        try:
            from bs4 import BeautifulSoup  # type: ignore

            pre = client.get(config.login_url)
            if pre is not None:
                soup = BeautifulSoup(pre.text or "", "html.parser")
                form = soup.find("form")
                if form:
                    for inp in form.find_all("input"):
                        n = inp.get("name")
                        v = inp.get("value")
                        if n and n not in data and inp.get("type") in ("hidden", None, "text"):
                            data.setdefault(n, v or "")
        except Exception:  # noqa: BLE001
            pass

        r = client.post(config.login_url, data=data, allow_redirects=True)
        if r is None:
            log.warning("[auth] Login request failed.")
            return False
        cookies = client.session.cookies
        captured = {c.name: c.value for c in cookies}
        if not captured:
            log.warning("[auth] No cookies set after login (status=%s).", r.status_code)
            return False
        # Propagate to config so subsequent HttpClient instances inherit it.
        config.cookies.update(captured)
        log.info("[auth] Login successful, %d cookies captured.", len(captured))
        return True
    finally:
        client.close()
