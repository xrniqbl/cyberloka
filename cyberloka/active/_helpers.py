"""Helpers shared by active checks."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


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
