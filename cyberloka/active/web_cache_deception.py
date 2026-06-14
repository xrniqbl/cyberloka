"""Web Cache Deception (WCD) detection — real, evidence-based.

Web Cache Deception tricks a CDN / reverse cache into storing an authenticated,
per-user page under a URL that *looks* like a static asset (e.g.
`/account/cyberloka.css`). A later anonymous visitor requesting the same URL is
served the victim's cached private page — account/PII disclosure with zero
authentication. It is rarely tested by scanners yet trivially devastating.

This module does NOT guess. It confirms in escalating, header-and-content
evidence levels:

  1. A personal endpoint P returns a per-user marker M *only when
     authenticated* (an anonymous request to P does NOT contain M).
  2. A static-looking variant S of P still returns M while authenticated AND the
     response is genuinely cacheable (Cache-Control public/max-age, or a CDN
     cache HIT) — the misroute + cache primitive.
  3. CONFIRMED: an anonymous request to S returns M — the cache literally served
     the victim's private content to an unauthenticated client.

Full confirmation needs an authenticated session (run with --login-url /
--login-username / --login-password, --auth-bearer, or --cookies). Without one,
WCD cannot be proven and the module stays silent rather than guessing.
"""
from __future__ import annotations

import re
from dataclasses import replace
from urllib.parse import urljoin, urlparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate
from cyberloka.recon.crawler import get_state

# Endpoints that commonly render per-user content.
DEFAULT_PERSONAL_PATHS = (
    "/account", "/account/", "/profile", "/profile/", "/settings", "/settings/",
    "/dashboard", "/me", "/user", "/users/me", "/api/me", "/api/user",
    "/api/account", "/billing", "/orders", "/wallet", "/inbox",
)

# Signals that a page is personalised (i.e. we are authenticated).
PERSONAL_HINTS = re.compile(
    r"(log\s?out|sign\s?out|keluar|my account|akun saya|saldo|balance|"
    r"profil saya|api[_-]?key|csrf[_-]?token|authenticity_token)",
    re.I,
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
CSRF_RE = re.compile(
    r'(?:csrf[_-]?token|authenticity_token)["\']?\s*[:=]\s*["\']([A-Za-z0-9._\-]{8,})',
    re.I,
)

PERSONAL_PATH_HINTS = (
    "account", "profile", "setting", "dashboard", "/me", "user", "billing",
    "order", "wallet", "inbox", "saldo",
)


def _anon_config(config: ScanConfig) -> ScanConfig:
    """Clone of config with no auth cookies and no Authorization header."""
    headers = {
        k: v for k, v in (config.headers or {}).items()
        if k.lower() != "authorization"
    }
    return replace(config, cookies={}, headers=headers)


def _is_cacheable(resp) -> tuple[bool, str]:
    """Read cacheability straight from response headers (no guessing)."""
    h = {k.lower(): v for k, v in resp.headers.items()}
    cc = h.get("cache-control", "").lower()
    if "no-store" in cc or "private" in cc:
        return False, f"cache-control={cc!r}"
    cached = False
    notes: list[str] = []
    if "public" in cc:
        cached = True
        notes.append("cache-control:public")
    m = re.search(r"max-age=(\d+)", cc)
    if m and int(m.group(1)) > 0:
        cached = True
        notes.append(f"max-age={m.group(1)}")
    for hk in ("x-cache", "cf-cache-status", "x-cache-status"):
        v = h.get(hk, "")
        if "hit" in v.lower():
            cached = True
            notes.append(f"{hk}={v}")
    age = h.get("age", "").strip()
    if age.isdigit() and int(age) > 0:
        cached = True
        notes.append(f"age={age}")
    return cached, ", ".join(notes) or f"cache-control={cc!r}"


def _served_from_cache(resp) -> bool:
    h = {k.lower(): v for k, v in resp.headers.items()}
    for hk in ("x-cache", "cf-cache-status", "x-cache-status"):
        if "hit" in h.get(hk, "").lower():
            return True
    age = h.get("age", "").strip()
    return age.isdigit() and int(age) > 0


def _marker(body: str, config: ScanConfig) -> str | None:
    """Pick a stable per-user string present in an authenticated body."""
    if not body:
        return None
    m = CSRF_RE.search(body)
    if m:
        return m.group(1)
    user = config.login_username or ""
    if user and user in body:
        return user
    m = EMAIL_RE.search(body)
    if m:
        return m.group(0)
    return None


def _variants(url: str) -> list[str]:
    """Static-looking path-confusion variants of an authenticated URL."""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    last = path.rsplit("/", 1)[-1] or "root"
    out: list[str] = []
    for ext in (".css", ".js", ".png"):
        out.append(parsed._replace(path=f"{path}/cyberloka_wcd{ext}").geturl())
        out.append(parsed._replace(path=f"{path}%2fcyberloka_wcd{ext}").geturl())
        out.append(parsed._replace(path=f"{path};cyberloka_wcd{ext}").geturl())
        out.append(parsed._replace(path=f"{path}%00cyberloka_wcd{ext}").geturl())
        out.append(parsed._replace(path=f"{path}/%2e%2e/{last}{ext}").geturl())
    seen: set[str] = set()
    uniq: list[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def _personal_urls(target: Target, config: ScanConfig) -> list[str]:
    origin = target.origin
    urls = [urljoin(origin, p) for p in DEFAULT_PERSONAL_PATHS]
    state = get_state(config)
    if state:
        for u in state.urls:
            pl = urlparse(u).path.lower()
            if any(s in pl for s in PERSONAL_PATH_HINTS):
                urls.append(u)
    seen: set[str] = set()
    uniq: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq[:20]


def _confirmed(s_url: str, p_url: str, marker: str, cache_ev: str,
               from_cache: bool) -> Finding:
    return Finding(
        module="web_cache_deception",
        title=f"Web Cache Deception terkonfirmasi pada `{urlparse(p_url).path}`",
        severity=Severity.CRITICAL,
        description=(
            "Permintaan ANONIM ke URL berekstensi statis "
            f"`{s_url}` mengembalikan konten privat milik user terautentikasi "
            "(marker per-user bocor). Cache menyimpan halaman akun dan "
            "menyajikannya ke pengunjung tanpa login → pengambilalihan "
            "data/akun tanpa kredensial."
        ),
        target=s_url,
        evidence=truncate(
            f"marker={marker!r} bocor ke anonim; cache=({cache_ev}); "
            f"served_from_cache={from_cache}", 240),
        cwe="CWE-525",
        confidence="confirmed",
        remediation=(
            "Cache hanya boleh menyimpan path yang benar-benar statis — "
            "cocokkan berdasarkan Content-Type asal, bukan ekstensi di URL. Set "
            "`Cache-Control: private, no-store` pada semua respons "
            "terautentikasi. Tolak penambahan ekstensi / path traversal di "
            "origin, dan pakai `Vary: Cookie` bila perlu."
        ),
        references=[
            "https://owasp.org/www-community/attacks/Web_Cache_Deception",
            "https://portswigger.net/research/web-cache-deception",
        ],
        extra={"personal_url": p_url, "cache_evidence": cache_ev},
    )


def _surface(s_url: str, p_url: str, cache_ev: str) -> Finding:
    return Finding(
        module="web_cache_deception",
        title=f"Permukaan Web Cache Deception pada `{urlparse(p_url).path}`",
        severity=Severity.HIGH,
        description=(
            "Halaman terautentikasi disajikan di bawah URL berekstensi statis "
            f"`{s_url}` dengan respons yang boleh di-cache. Bila ada cache di "
            "depan origin yang menyimpan respons ini, pengunjung anonim dapat "
            "menerima konten privat (Web Cache Deception)."
        ),
        target=s_url,
        evidence=truncate(
            "marker per-user muncul pada URL statis saat terautentikasi; "
            f"cacheable=({cache_ev})", 240),
        cwe="CWE-525",
        confidence="firm",
        remediation=(
            "Set `Cache-Control: private, no-store` untuk semua respons "
            "terautentikasi dan tentukan cache berdasarkan Content-Type asli, "
            "bukan ekstensi URL."
        ),
        references=[
            "https://owasp.org/www-community/attacks/Web_Cache_Deception",
        ],
        extra={"personal_url": p_url},
    )


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    authed = HttpClient(config)
    anon = HttpClient(_anon_config(config))
    try:
        for p_url in _personal_urls(target, config):
            base = authed.get(p_url)
            if base is None or base.status_code != 200:
                continue
            body = base.text or ""
            marker = _marker(body, config)
            # Need a per-user marker AND a personalisation signal to proceed.
            if not marker or not (PERSONAL_HINTS.search(body) or "@" in marker):
                continue
            # P must be auth-gated: anonymous P should NOT leak the marker.
            anon_base = anon.get(p_url)
            if anon_base is not None and marker in (anon_base.text or ""):
                continue  # endpoint is simply public → not WCD

            for s_url in _variants(p_url):
                rs = authed.get(s_url)
                if rs is None or rs.status_code != 200:
                    continue
                if marker not in (rs.text or ""):
                    continue  # extension not ignored → no misroute
                cacheable, cache_ev = _is_cacheable(rs)
                if not cacheable:
                    continue  # served but not cacheable → no exposure

                ra = anon.get(s_url)  # REAL confirmation
                if ra is not None and marker in (ra.text or ""):
                    findings.append(
                        _confirmed(s_url, p_url, marker, cache_ev,
                                   _served_from_cache(ra)))
                else:
                    findings.append(_surface(s_url, p_url, cache_ev))
                break  # one finding per endpoint is enough
    finally:
        authed.close()
        anon.close()
    return findings
