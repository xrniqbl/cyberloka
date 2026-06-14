"""Target normalisation."""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse


@dataclass
class Target:
    raw: str
    scheme: str
    host: str
    port: int
    path: str
    is_ip: bool
    query: str = ""

    @property
    def base_url(self) -> str:
        netloc = self.host
        if (self.scheme == "http" and self.port != 80) or (
            self.scheme == "https" and self.port != 443
        ):
            netloc = f"{self.host}:{self.port}"
        return urlunparse((self.scheme, netloc, self.path or "/", "", self.query, ""))

    @property
    def origin(self) -> str:
        netloc = self.host
        if (self.scheme == "http" and self.port != 80) or (
            self.scheme == "https" and self.port != 443
        ):
            netloc = f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}"

    def resolve_ip(self) -> str | None:
        if self.is_ip:
            return self.host
        try:
            return socket.gethostbyname(self.host)
        except OSError:
            return None


def parse_target(raw: str) -> Target:
    """Parse user-provided target string into a Target object."""
    raw = raw.strip()
    if "://" not in raw:
        # bare host or ip
        try:
            ipaddress.ip_address(raw.split(":")[0])
            scheme = "http"
        except ValueError:
            scheme = "https"
        raw_with_scheme = f"{scheme}://{raw}"
    else:
        raw_with_scheme = raw

    parsed = urlparse(raw_with_scheme)
    scheme = parsed.scheme.lower() or "https"
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError(f"Invalid target: {raw}")

    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    return Target(
        raw=raw,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        is_ip=is_ip,
        query=parsed.query or "",
    )
