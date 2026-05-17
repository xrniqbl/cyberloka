"""Helpers shared by active checks."""
from __future__ import annotations

from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import Target


def has_query(url: str) -> bool:
    return bool(urlparse(url).query)


def iter_param_urls(url: str, payload: str):
    """Yield (param, mutated_url) for each query parameter, replacing its value with payload."""
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return
    for i, (k, _) in enumerate(params):
        new = list(params)
        new[i] = (k, payload)
        new_q = urlencode(new, doseq=True)
        yield k, urlunparse(parsed._replace(query=new_q))


def append_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    params.append((key, value))
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def collect_target_urls(target: Target, default_param: str = "q") -> Iterable[str]:
    """Kumpulkan URL kandidat untuk modul aktif.

    Prioritas:
    1) Endpoint hasil crawler (target.discovered) yang punya parameter.
    2) target.base_url; bila tidak ada query string, tambahkan default param.
    """
    seen: set[str] = set()
    discovered = getattr(target, "discovered", None)
    if discovered is not None:
        for ep in getattr(discovered, "endpoints", []):
            if ep.method != "GET":
                continue
            url = ep.url
            if "?" not in url:
                if not ep.params:
                    continue
                # form GET yang fields-nya jadi query
                url = append_param(url, ep.params[0], "test")
            if url in seen:
                continue
            seen.add(url)
            yield url

    base = target.base_url
    if "?" not in base:
        base = append_param(base, default_param, "test")
    if base not in seen:
        yield base
