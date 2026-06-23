"""Lightweight in-scope HTML crawler.

Discovers URLs, parameters, and forms by following same-origin links
breadth-first. Output is consumed by other modules (sqli/xss/forms/csrf).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

# attached to ScanConfig.extra_state at runtime by the scanner
_SHARED_KEY = "_crawler_state"


@dataclass
class CrawlState:
    urls: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)  # {action,method,inputs:[{name,type,value}]}
    param_urls: list[str] = field(default_factory=list)  # urls that contain query params

    @property
    def summary(self) -> dict:
        return {
            "urls": len(self.urls),
            "forms": len(self.forms),
            "param_urls": len(self.param_urls),
        }


def get_state(config: ScanConfig) -> CrawlState | None:
    return getattr(config, _SHARED_KEY, None)


def _set_state(config: ScanConfig, state: CrawlState) -> None:
    setattr(config, _SHARED_KEY, state)


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


def _extract(soup: BeautifulSoup, base: str) -> tuple[list[str], list[dict]]:
    links: list[str] = []
    for tag in soup.find_all(["a", "link"]):
        href = tag.get("href")
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        url, _ = urldefrag(urljoin(base, href))
        links.append(url)
    forms: list[dict] = []
    for f in soup.find_all("form"):
        action = urljoin(base, f.get("action") or base)
        method = (f.get("method") or "get").lower()
        inputs = []
        for el in f.find_all(["input", "textarea", "select"]):
            name = el.get("name")
            if not name:
                continue
            inputs.append(
                {
                    "name": name,
                    "type": (el.get("type") or el.name or "text").lower(),
                    "value": el.get("value") or "",
                }
            )
        forms.append({"action": action, "method": method, "inputs": inputs})
    return links, forms


def run(target: Target, config: ScanConfig) -> list[Finding]:
    """Crawl up to N pages and stash results in config for downstream modules."""
    max_pages = int(getattr(config, "max_crawl_pages", 30))
    state = CrawlState()
    _set_state(config, state)

    client = HttpClient(config)
    seen: set[str] = set()
    queue: deque[str] = deque([target.base_url])
    base = target.origin

    try:
        while queue and len(seen) < max_pages:
            url = queue.popleft()
            if url in seen or not _same_origin(url, base):
                continue
            seen.add(url)
            resp = client.get(url)
            if resp is None or resp.status_code >= 400:
                continue
            ctype = resp.headers.get("Content-Type", "").lower()
            if "html" not in ctype:
                continue
            soup = BeautifulSoup(resp.text or "", "html.parser")
            links, forms = _extract(soup, url)
            state.urls.append(url)
            if "?" in url:
                state.param_urls.append(url)
            for form in forms:
                if _same_origin(form["action"], base):
                    state.forms.append(form)
            for lk in links:
                if lk not in seen and _same_origin(lk, base):
                    queue.append(lk)
    finally:
        client.close()

    return [
        Finding(
            module="crawler",
            title="Crawler discovery",
            severity=Severity.INFO,
            description=(
                f"Crawler menyusuri {len(state.urls)} URL, menemukan {len(state.forms)} "
                f"form, dan {len(state.param_urls)} URL dengan parameter query. "
                "Hasil ini dipakai modul lain untuk pengujian yang lebih dalam."
            ),
            target=target.base_url,
            evidence="\n".join(state.urls[:30]),
            confidence="confirmed",
            extra={"summary": state.summary},
        )
    ]
