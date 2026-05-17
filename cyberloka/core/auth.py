"""Authenticated scan support.

Mendukung 3 mekanisme:
- Form login (POST credentials, ekstrak CSRF token otomatis dari form bila ada)
- Bearer token (header Authorization)
- Raw cookie / header injection (sudah ditangani ScanConfig)

Setelah login, cookie disuntik ke HttpClient.session sehingga semua modul
(passive + active + simulate) berjalan dalam konteks terotentikasi.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import requests

from cyberloka.core.logger import get_logger

CSRF_FIELD_HINTS = (
    "csrf",
    "csrfmiddlewaretoken",
    "_token",
    "authenticity_token",
    "__requestverificationtoken",
    "xsrf",
)


@dataclass
class AuthConfig:
    """Konfigurasi otentikasi."""

    method: str = "none"  # none | form | bearer
    login_url: str | None = None
    username: str | None = None
    password: str | None = None
    user_field: str = "username"
    pass_field: str = "password"
    extra_form_fields: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None
    success_marker: str | None = None  # regex yang harus muncul di response setelah login
    failure_marker: str | None = None  # regex yang menandakan login gagal
    logout_url: str | None = None  # diserahkan ke crawler untuk dihindari


def _extract_csrf(html: str) -> dict[str, str]:
    """Extract hidden form fields yang terlihat seperti CSRF token."""
    fields: dict[str, str] = {}
    # match <input name=".." value=".."> dengan urutan atribut bebas
    pattern = re.compile(
        r'<input\b[^>]*?name=["\']([^"\']+)["\'][^>]*?value=["\']([^"\']*)["\']',
        re.IGNORECASE,
    )
    for m in pattern.finditer(html):
        name = m.group(1)
        if any(h in name.lower() for h in CSRF_FIELD_HINTS):
            fields[name] = m.group(2)
    # juga cari pola: value="..." name="..." (atribut terbalik)
    pattern2 = re.compile(
        r'<input\b[^>]*?value=["\']([^"\']*)["\'][^>]*?name=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    for m in pattern2.finditer(html):
        name = m.group(2)
        if any(h in name.lower() for h in CSRF_FIELD_HINTS):
            fields.setdefault(name, m.group(1))
    return fields


def authenticate(session: requests.Session, auth: AuthConfig) -> tuple[bool, str]:
    """Lakukan otentikasi pada session. Return (ok, message)."""
    log = get_logger()
    if auth.method == "none":
        return True, "no auth"

    if auth.method == "bearer":
        if not auth.bearer_token:
            return False, "bearer method requires --auth-token"
        session.headers["Authorization"] = f"Bearer {auth.bearer_token}"
        return True, "bearer token attached"

    if auth.method == "form":
        if not (auth.login_url and auth.username and auth.password):
            return False, "form auth needs --login-url, --auth-user, --auth-pass"
        # 1. GET login page untuk ambil cookies awal + CSRF token
        try:
            pre = session.get(auth.login_url, timeout=10, allow_redirects=True)
        except requests.RequestException as e:
            return False, f"GET {auth.login_url} gagal: {e}"
        csrf = _extract_csrf(pre.text or "")
        if csrf:
            log.info("CSRF token terdeteksi: %s", list(csrf))

        # 2. POST credentials
        data: dict[str, Any] = {
            auth.user_field: auth.username,
            auth.pass_field: auth.password,
        }
        data.update(csrf)
        data.update(auth.extra_form_fields)

        # Beberapa app mengharapkan Referer = login page
        post_url = urljoin(pre.url or auth.login_url, auth.login_url)
        try:
            resp = session.post(
                post_url,
                data=data,
                timeout=10,
                allow_redirects=True,
                headers={"Referer": pre.url or auth.login_url},
            )
        except requests.RequestException as e:
            return False, f"POST {post_url} gagal: {e}"

        body = resp.text or ""
        # 3. Cek hasil
        if auth.failure_marker and re.search(auth.failure_marker, body, re.IGNORECASE):
            return False, "failure_marker cocok pada response"
        if auth.success_marker and not re.search(auth.success_marker, body, re.IGNORECASE):
            return False, "success_marker tidak ditemukan"
        # Heuristik default: status 200/302 + ada cookie baru
        if not session.cookies:
            return False, "tidak ada cookie session yang diset"
        return True, f"login OK (status={resp.status_code}, {len(session.cookies)} cookies)"

    return False, f"metode auth tidak dikenal: {auth.method}"
