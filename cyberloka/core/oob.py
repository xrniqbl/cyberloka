"""Out-of-band (OAST) collaborator client for confirming blind vulnerabilities.

Safe by design: this only generates benign callback URLs and polls a
self-hosted collaborator server to see whether a request arrived. It
never sends payloads, never exploits, and never acts on a target.
"""
from __future__ import annotations

import secrets
import time
from urllib.parse import urlparse

import requests

TOKEN_PREFIX = "cl"


class OOBClient:
    """Talks to a self-hosted cyberloka collaborator server.

    `base_url` is the publicly-reachable collaborator the user controls
    (e.g. http://oast.example.com:8088). The scanner injects
    `payload_url(token)` into target parameters; if the target makes an
    outbound request, the collaborator logs it and `poll(token)` returns
    the recorded hits.
    """

    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    @property
    def host(self) -> str:
        return urlparse(self.base_url).netloc

    def new_token(self) -> str:
        return TOKEN_PREFIX + secrets.token_hex(8)

    def payload_url(self, token: str) -> str:
        """Benign callback URL to inject into a URL-like parameter."""
        return f"{self.base_url}/{token}"

    def payload_host(self, token: str) -> str:
        """Host-based callback target (token as subdomain) for DNS/SSRF."""
        return f"{token}.{self.host}"

    def poll(self, token: str) -> list[dict]:
        try:
            r = requests.get(
                f"{self.base_url}/_cyberloka/poll/{token}", timeout=self.timeout
            )
            if r.status_code != 200:
                return []
            return r.json().get("hits", [])
        except (requests.RequestException, ValueError):
            return []

    def wait_for_hit(
        self, token: str, attempts: int = 3, delay: float = 1.5
    ) -> list[dict]:
        """Poll a few times to allow for async server-side fetches."""
        for _ in range(attempts):
            hits = self.poll(token)
            if hits:
                return hits
            time.sleep(delay)
        return []
