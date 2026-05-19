"""Grafana default credentials (admin/admin) detection.

Auto-validation: POST ke /login dengan admin/admin. Validasi cookie session
`grafana_session` muncul + GET /api/datasources balas 200 (bukan 401).
"""
from __future__ import annotations

import json
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

LOGIN_PATH = "/login"
DS_PATH = "/api/datasources"
HOMEPAGE_PATHS = ("/", "/login")
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "Admin"),
    ("admin", "grafana"),
]


def _is_grafana(text: str) -> bool:
    head = text[:8192].lower()
    return ('grafana' in head and ('window.grafanabootdata' in head
                                   or 'grafana_session' in head
                                   or 'login form' in head
                                   or 'data-content="grafana"' in head))


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        # Konfirmasi instance Grafana
        is_grafana = False
        for p in HOMEPAGE_PATHS:
            r = client.get(urljoin(target.origin + "/", p.lstrip("/")),
                           allow_redirects=False)
            if r is None:
                continue
            if _is_grafana(r.text or "") or "Grafana" in r.headers.get("Set-Cookie", ""):
                is_grafana = True
                break
        if not is_grafana:
            return findings

        login_url = urljoin(target.origin + "/", LOGIN_PATH.lstrip("/"))
        ds_url = urljoin(target.origin + "/", DS_PATH.lstrip("/"))
        for user, pwd in DEFAULT_CREDS:
            payload = json.dumps({"user": user, "password": pwd})
            client.session.cookies.clear()
            r = client.post(login_url, data=payload,
                            headers={"Content-Type": "application/json"},
                            allow_redirects=False)
            if r is None:
                continue
            session_cookie = any(
                c.name.lower() in ("grafana_session", "grafana_sess")
                for c in client.session.cookies
            )
            # Validate by fetching /api/datasources (admin-only)
            ds = client.get(ds_url, allow_redirects=False) if session_cookie else None
            if not session_cookie:
                continue
            if ds is None or ds.status_code != 200:
                continue

            findings.append(Finding(
                module="grafana_default_login",
                title=f"Grafana default credentials valid: `{user}` / `{pwd}`",
                severity=Severity.CRITICAL,
                description=(
                    "Grafana mengizinkan login dengan kredensial default "
                    f"`{user}/{pwd}` dan menerbitkan session admin. "
                    "Datasource Grafana sering memuat connection string "
                    "production database."
                ),
                target=login_url,
                urls=[login_url, ds_url],
                evidence=(
                    f"POST {login_url} {user}/{pwd} -> session terbentuk; "
                    f"GET {ds_url} -> {ds.status_code} (akses admin)"
                ),
                cwe="CWE-798",
                confidence="confirmed",
                remediation=(
                    "Ubah password admin segera. Set `disable_initial_admin_creation` "
                    "atau provision via env GF_SECURITY_ADMIN_PASSWORD. Aktifkan "
                    "OAuth/SAML SSO. Wajibkan 2FA. Tutup signup publik."
                ),
                references=[
                    "https://grafana.com/docs/grafana/latest/administration/security/",
                ],
            ))
            break
    finally:
        client.close()
    return findings
