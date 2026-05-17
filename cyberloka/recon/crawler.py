"""Lightweight in-scope crawler / spider.

- Mulai dari base URL, ikuti link `<a href>`, `<form action>`, `<script src>`,
  `<link href>`, dan ekstrak parameter dari query string + form fields.
- Hanya mengikuti link yang same-origin (host == target.host).
- Mempersistensi temuan ke `target.discovered` agar modul aktif (XSS, SQLi, dll.)
  bisa memakainya. Modul aktif tetap berjalan default (mode lama) bila tidak ada.
- Capped: max_pages, max_depth, dan menghormati rate limiter.
"""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlparse, parse_qsl, urlencode, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

DEFAULT_MAX_PAGES = 60
DEFAULT_MAX_DEPTH = 3

# Path yang dihindari supaya scan tidak logout / merusak state
DANGEROUS_KEYWORDS = ("logout", "signout", "sign-out", "delete", "destroy", "remove", "purge")


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    source: str = "link"  # link | form | script | inline


@dataclass
class CrawlResult:
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    js_urls: list[str] = field(default_factory=list)
    visited: list[str] = field(default_factory=list)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict] = []
        self._cur_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        t = tag.lower()
        if t == "a" and a.get("href"):
            self.links.append(a["href"])
        elif t == "link" and a.get("href"):
            self.links.append(a["href"])
        elif t == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif t == "iframe" and a.get("src"):
            self.links.append(a["src"])
        elif t == "form":
            self._cur_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "GET").upper(),
                "fields": [],
            }
        elif t in ("input", "textarea", "select") and self._cur_form is not None:
            name = a.get("name")
            if name:
                self._cur_form["fields"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None


JS_URL_RE = re.compile(r'["\'](?P<u>(?:/[A-Za-z0-9_\-./?=&%]+|https?://[^"\']+))["\']')


def _extract_js_urls(body: str, max_count: int = 30) -> list[str]:
    out: set[str] = set()
    for m in JS_URL_RE.finditer(body):
        u = m.group("u")
        if any(u.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2", ".ico", ".map")):
            continue
        out.add(u)
        if len(out) >= max_count:
            break
    return list(out)


def _normalize(url: str) -> str:
    url, _ = urldefrag(url)
    p = urlparse(url)
    # canonicalize query order
    if p.query:
        params = sorted(parse_qsl(p.query, keep_blank_values=True))
        url = urlunparse(p._replace(query=urlencode(params, doseq=True)))
    return url


def _in_scope(url: str, host: str) -> bool:
    try:
        h = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return h == host.lower()


def _is_dangerous(url: str) -> bool:
    lower = url.lower()
    return any(k in lower for k in DANGEROUS_KEYWORDS)


def crawl(
    target: Target,
    config: ScanConfig,
    client: HttpClient | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> CrawlResult:
    """Lakukan crawl in-scope dan kembalikan endpoint yang ditemukan."""
    own_client = client is None
    client = client or HttpClient(config)
    result = CrawlResult()
    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(target.base_url, 0)])

    try:
        while queue and len(result.visited) < max_pages:
            url, depth = queue.popleft()
            url = _normalize(url)
            if url in seen or _is_dangerous(url):
                continue
            seen.add(url)
            if not _in_scope(url, target.host):
                continue

            resp = client.get(url, allow_redirects=False)
            if resp is None:
                continue
            result.visited.append(url)

            ctype = resp.headers.get("Content-Type", "").lower()
            # Catat endpoint dengan param query
            p = urlparse(url)
            qs_params = [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]
            result.endpoints.append(
                DiscoveredEndpoint(url=url, method="GET", params=qs_params, source="link")
            )

            if "html" not in ctype and "xml" not in ctype:
                continue

            body = resp.text or ""
            parser = _LinkParser()
            try:
                parser.feed(body)
            except Exception:  # noqa: BLE001
                pass

            # Forms
            for f in parser.forms:
                action = urljoin(url, f["action"]) if f["action"] else url
                if not _in_scope(action, target.host):
                    continue
                result.forms.append({
                    "url": action,
                    "method": f["method"],
                    "fields": f["fields"],
                })
                result.endpoints.append(
                    DiscoveredEndpoint(
                        url=action,
                        method=f["method"],
                        params=list(f["fields"]),
                        source="form",
                    )
                )

            # Links
            if depth < max_depth:
                for link in parser.links:
                    if link.startswith(("mailto:", "tel:", "javascript:")):
                        continue
                    nxt = urljoin(url, link)
                    if _in_scope(nxt, target.host) and not _is_dangerous(nxt):
                        queue.append((nxt, depth + 1))

            # Scripts -> ekstrak URL & param hint
            for s in parser.scripts:
                full = urljoin(url, s)
                if _in_scope(full, target.host):
                    result.js_urls.append(full)

            # URL strings di body
            for u in _extract_js_urls(body):
                full = urljoin(url, u)
                if _in_scope(full, target.host) and not _is_dangerous(full):
                    pn = urlparse(full)
                    pms = [k for k, _ in parse_qsl(pn.query, keep_blank_values=True)]
                    result.endpoints.append(
                        DiscoveredEndpoint(url=full, method="GET", params=pms, source="inline")
                    )
    finally:
        if own_client:
            client.close()

    # Dedup endpoints: by (method, url-without-query, set(params))
    dedup: dict[tuple, DiscoveredEndpoint] = {}
    for ep in result.endpoints:
        p = urlparse(ep.url)
        base = urlunparse(p._replace(query="", fragment=""))
        key = (ep.method, base, tuple(sorted(ep.params)))
        if key not in dedup or len(ep.params) > len(dedup[key].params):
            dedup[key] = ep
    result.endpoints = list(dedup.values())
    return result


def run(target: Target, config: ScanConfig) -> list[Finding]:
    """Modul crawler: jalankan & laporkan ringkasan sebagai INFO finding.

    Endpoint yang ditemukan akan di-attach ke `target.discovered` agar modul
    aktif lain dapat memakainya.
    """
    res = crawl(target, config)
    # attach untuk modul aktif
    setattr(target, "discovered", res)

    if not res.visited:
        return []

    paramed = [e for e in res.endpoints if e.params]
    forms = res.forms
    return [
        Finding(
            module="crawler",
            title=f"Crawler menemukan {len(res.endpoints)} endpoint ({len(paramed)} dengan parameter)",
            severity=Severity.INFO,
            description=(
                f"Spider mengunjungi {len(res.visited)} halaman in-scope. "
                f"Ditemukan {len(forms)} form dan {len(res.js_urls)} script. "
                "Modul aktif (XSS, SQLi, LFI, dll.) akan menggunakan daftar ini "
                "sebagai target tambahan."
            ),
            target=target.base_url,
            evidence=(
                "Visited (sampel):\n"
                + "\n".join(f"  {u}" for u in res.visited[:10])
                + (f"\n  ... +{len(res.visited) - 10} lagi" if len(res.visited) > 10 else "")
                + "\n\nEndpoints dgn parameter (sampel):\n"
                + "\n".join(f"  [{e.method}] {e.url} ({','.join(e.params)})" for e in paramed[:10])
            ),
            extra={
                "visited": res.visited,
                "endpoints": [
                    {"url": e.url, "method": e.method, "params": e.params, "source": e.source}
                    for e in res.endpoints
                ],
                "forms": res.forms,
                "js_urls": res.js_urls,
            },
        )
    ]
