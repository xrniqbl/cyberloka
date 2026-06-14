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


def candidate_urls(target, config, synth_key, synth_val, cap=25):
    """URLs an active param-based check should test.

    Pulls parameterised URLs discovered by the crawler so checks reach query
    params on linked sub-pages, not just the homepage. Always includes the
    target base URL as a fallback (with a synthetic param appended when it has
    no query string of its own). De-duplicates and caps the list.
    """
    from cyberloka.recon.crawler import get_state

    out: list[str] = []
    seen: set[str] = set()

    def _add(u: str) -> None:
        if not u:
            return
        if not has_query(u):
            u = append_param(u, synth_key, synth_val)
        if u not in seen:
            seen.add(u)
            out.append(u)

    state = get_state(config)
    if state:
        for u in state.param_urls:
            _add(u)
    _add(target.base_url)
    return out[:cap]
