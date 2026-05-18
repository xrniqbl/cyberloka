"""Helpers shared by active checks."""
from __future__ import annotations

import statistics
import time
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cyberloka.core import HttpClient


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


def replace_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    new = [(k, value) if k == key else (k, v) for k, v in params]
    if not any(k == key for k, _ in params):
        new.append((key, value))
    return urlunparse(parsed._replace(query=urlencode(new, doseq=True)))


# ---------------------------------------------------------------------------
# Baseline / diff helpers
# ---------------------------------------------------------------------------
def baseline(client: HttpClient, url: str, samples: int = 2) -> dict | None:
    """Capture baseline response for ``url`` (status, length, latency)."""
    statuses: list[int] = []
    lengths: list[int] = []
    latencies: list[float] = []
    body = ""
    headers: dict[str, str] = {}
    for _ in range(max(1, samples)):
        t0 = time.monotonic()
        resp = client.get(url, allow_redirects=False)
        dt = time.monotonic() - t0
        if resp is None:
            continue
        statuses.append(resp.status_code)
        body = resp.text or ""
        lengths.append(len(body))
        latencies.append(dt)
        headers = dict(resp.headers)
    if not statuses:
        return None
    return {
        "status": statuses[-1],
        "length": int(statistics.median(lengths)) if lengths else 0,
        "latency": statistics.median(latencies) if latencies else 0.0,
        "body": body,
        "headers": headers,
    }


def diff_significant(base: dict, resp_status: int, resp_text: str) -> bool:
    """Return True when the new response materially differs from the baseline."""
    if base is None:
        return False
    if resp_status != base["status"]:
        return True
    blen = base["length"] or 1
    new_len = len(resp_text or "")
    # > 200 byte AND >5% relative change
    return abs(new_len - blen) > 200 and abs(new_len - blen) / blen > 0.05


def stable_latency(client: HttpClient, url: str, samples: int = 3) -> float:
    """Return median request latency for ``url``."""
    lats: list[float] = []
    for _ in range(samples):
        t0 = time.monotonic()
        r = client.get(url, allow_redirects=False)
        if r is None:
            continue
        lats.append(time.monotonic() - t0)
    return statistics.median(lats) if lats else 0.0


def candidate_params(url: str, hints: Iterable[str] = ("id", "q", "search", "page", "file", "name")) -> list[str]:
    """Return existing query params, falling back to a small list of common names."""
    parsed = urlparse(url)
    params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    return params or list(hints)

