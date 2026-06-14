"""Helpers shared by active checks."""
from __future__ import annotations

import difflib
import re
import statistics
import time
from dataclasses import dataclass
from typing import Any
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


# ---------------------------------------------------------------------------
# Verification primitives (verification-first active scanning)
#
# Tujuan: sebuah temuan hanya boleh dilaporkan bila bisa DIBUKTIKAN lewat
# pembandingan terhadap respons baseline + permintaan kontrol — bukan sekadar
# satu pola di satu respons. Ini menghilangkan false positive.
# ---------------------------------------------------------------------------


def param_items(url: str) -> list[tuple[str, str]]:
    return parse_qsl(urlparse(url).query, keep_blank_values=True)


def param_names(url: str) -> list[str]:
    seen: list[str] = []
    for k, _ in param_items(url):
        if k not in seen:
            seen.append(k)
    return seen


def get_param_value(url: str, param: str) -> str:
    for k, v in param_items(url):
        if k == param:
            return v
    return ""


def replace_param(url: str, param: str, value: str) -> str:
    """Return a copy of `url` with the first occurrence of `param` set to `value`,
    round-tripping through proper URL encoding."""
    parsed = urlparse(url)
    done = False
    new: list[tuple[str, str]] = []
    for k, v in param_items(url):
        if k == param and not done:
            new.append((k, value))
            done = True
        else:
            new.append((k, v))
    return urlunparse(parsed._replace(query=urlencode(new, doseq=True)))


def _normalise(text: str) -> str:
    """Strip volatile bits (tokens, timestamps, nonces) so two renders of the same
    logical page compare as near-identical — robust against benign dynamic content."""
    text = re.sub(r"[0-9a-fA-F]{16,}", "", text)
    text = re.sub(r"\b\d{10,}\b", "", text)
    text = re.sub(r"csrf[-_]?token[\"'=:\s]+[\w\-]+", "", text, flags=re.I)
    text = re.sub(r"nonce[\"'=:\s]+[\w\-]+", "", text, flags=re.I)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def similarity(a: str | None, b: str | None) -> float:
    """Ratio 0..1 of how similar two response bodies are (after normalisation)."""
    if not a and not b:
        return 1.0
    if a is None or b is None:
        return 0.0
    a2, b2 = _normalise(a), _normalise(b)
    if not a2 and not b2:
        return 1.0
    return difflib.SequenceMatcher(None, a2, b2).ratio()


@dataclass
class Sample:
    status: int
    length: int
    text: str
    elapsed: float


def fetch(client: Any, url: str, **kw: Any) -> "Sample | None":
    """GET a URL and return a Sample (status, length, text, elapsed) or None."""
    start = time.monotonic()
    resp = client.get(url, **kw)
    elapsed = time.monotonic() - start
    if resp is None:
        return None
    text = resp.text or ""
    return Sample(status=resp.status_code, length=len(text), text=text, elapsed=elapsed)


def baseline_timing(client: Any, url: str, rounds: int = 3) -> float:
    """Median benign response time — the latency floor a time-based injection must beat."""
    times: list[float] = []
    for _ in range(max(1, rounds)):
        s = fetch(client, url)
        if s is not None:
            times.append(s.elapsed)
    return statistics.median(times) if times else 0.0