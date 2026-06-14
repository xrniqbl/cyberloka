"""Helpers shared by active checks."""
from __future__ import annotations

import re
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


# Forms whose submission could trigger a destructive / side-effecting action.
# We never fuzz these even under --authorized, to stay polite and safe.
_DANGEROUS_FORM = re.compile(
    r"(logout|sign[\-_]?out|delete|deactivate|remove|destroy|pay|checkout|"
    r"purchase|order|transfer|withdraw|unsubscribe|close[\-_]?account)",
    re.I,
)
_SKIP_INPUT_TYPES = {"submit", "button", "reset", "file", "hidden", "image"}


def fuzz_forms(client, config, payload, *, max_forms=10, max_fields=12):
    """Submit each crawler-discovered form with one field set to `payload`.

    Yields (field_name, action, response) for every fuzzable field in every
    discovered same-origin form. Non-target fields keep a benign default so the
    request stays well-formed. Destructive-looking forms are skipped.
    """
    from cyberloka.recon.crawler import get_state

    state = get_state(config)
    if not state:
        return
    for form in state.forms[:max_forms]:
        action = form.get("action") or ""
        method = (form.get("method") or "get").lower()
        inputs = form.get("inputs") or []
        names = " ".join((i.get("name") or "") for i in inputs)
        if _DANGEROUS_FORM.search(action) or _DANGEROUS_FORM.search(names):
            continue
        fuzzable = [
            i for i in inputs
            if i.get("name") and (i.get("type") or "text").lower() not in _SKIP_INPUT_TYPES
        ][:max_fields]
        for target in fuzzable:
            data: dict[str, str] = {}
            for i in inputs:
                name = i.get("name")
                if not name:
                    continue
                data[name] = payload if i is target else (i.get("value") or "test")
            resp = (client.post(action, data=data) if method == "post"
                    else client.get(action, params=data))
            if resp is not None:
                yield target.get("name"), action, resp
