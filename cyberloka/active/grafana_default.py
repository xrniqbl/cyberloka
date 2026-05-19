"""Grafana: deteksi versi + login dengan default admin/admin.

Validasi:
  1. GET /api/health -> harus return JSON {"version": "...", "database": "..."}
  2. POST /login dengan admin/admin (default Grafana yang sering tidak diganti).
     Sukses kalau response 302 ke / atau status 200 dengan Set-Cookie 'grafana_session'.
  3. Setelah cookie terdapat, GET /api/user untuk konfirmasi user 'admin' aktif.
  4. Cek apakah versi Grafana < 8.3.1 (CVE-2021-43798 path traversal).
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = ("/", "/grafana/", "/monitor/grafana/", "/dashboards/")

CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "grafana"),
    ("admin", "admin123"),
]


def _ver_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def _detect_grafana(client: HttpClient, base: str) -> tuple[str, str] | None:
    """Returns (grafana_base_url, version) or None."""
    for p in PATHS:
        api_url = urljoin(base, p.lstrip("/") + "api/health")
        r = client.get(api_url)
        if r is None or r.status_code != 200:
            continue
        try:
            d = r.json()
        except Exception:
            continue
        if isinstance(d, dict) and "version" in d and "database" in d:
            return urljoin(base, p), str(d.get("version"))
    return None


def _try_login(client: HttpClient, gbase: str, user: str, pwd: str) -> bool:
    client.session.cookies.clear()
    r = client.post(
        urljoin(gbase, "login"),
        json={"user": user, "password": pwd},
        headers={"Content-Type": "application/json"},
        allow_redirects=False,
    )
    if r is None:
        return False
    cookies = [c.name.lower() for c in r.cookies] if hasattr(r, "cookies") else []
    has_session = any("grafana_session" in c for c in cookies)
    if r.status_code == 200 and has_session:
        # Konfirmasi via /api/user
        u = client.get(urljoin(gbase, "api/user"))
        if u is not None and u.status_code == 200:
            try:
                ud = u.json()
            except Exception:
                return False
            if isinstance(ud, dict) and ud.get("login") == user:
                return True
    return False


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.base_url
    client = HttpClient(config)
    try:
        det = _detect_grafana(client, base)
        if det is None:
            return findings
        gbase, version = det
        ev = [f"Grafana base: {gbase}", f"Version: {version}"]

        # Cek CVE versi
        cve_old = False
        try:
            if _ver_tuple(version) < (8, 3, 1):
                cve_old = True
                ev.append("VERSION < 8.3.1 -> CVE-2021-43798 (path traversal -> read /etc/passwd)")
        except Exception:
            pass

        # Coba login default
        login_user, login_pass = "", ""
        for u, p in CREDS:
            if _try_login(client, gbase, u, p):
                login_user, login_pass = u, p
                ev.append(f"DEFAULT LOGIN OK: {u}/{p} (grafana_session set, /api/user confirms)")
                break

        if not (cve_old or login_user):
            findings.append(Finding(
                module="grafana_default",
                target=gbase,
                title=f"Grafana {version} terdeteksi (informasional)",
                severity=Severity.LOW,
                description=(
                    "Grafana dapat diakses publik tetapi password admin sudah "
                    "diganti dan versinya cukup baru."
                ),
                evidence="\n".join(ev),
                cwe="CWE-200",
                confidence="confirmed",
                urls=[gbase],
                remediation="Letakkan Grafana di belakang VPN/IP-allowlist untuk hardening lanjut.",
            ))
            return findings

        sev = Severity.CRITICAL if login_user else Severity.HIGH
        title_parts = []
        if login_user:
            title_parts.append(f"login default {login_user}/{login_pass} berhasil")
        if cve_old:
            title_parts.append("versi rentan CVE-2021-43798")

        findings.append(Finding(
            module="grafana_default",
            target=gbase,
            title=f"Grafana {version}: " + " + ".join(title_parts),
            severity=sev,
            description=(
                "Grafana terbuka dan "
                + (
                    "menerima kredensial default. Validasi multi-signal: "
                    "POST /login berhasil, cookie grafana_session ter-set, "
                    "dan GET /api/user mengembalikan user yang sama. "
                    if login_user else
                    "berjalan di versi lama yang punya CVE path traversal "
                    "(CVE-2021-43798). Attacker bisa baca /etc/passwd via plugin path. "
                )
                + "Grafana admin = bisa konfigur datasource (akses DB internal), "
                "buat alert webhook ke domain attacker (data exfil), atau jalankan "
                "query SQL ke datasource tersambung."
            ),
            evidence="\n".join(ev),
            cwe="CWE-798" if login_user else "CWE-1035",
            confidence="confirmed",
            urls=[gbase, urljoin(gbase, "login")],
            remediation=(
                "1. Login sebagai admin -> Settings -> Change password (minimal 16 char).\n"
                "2. Update Grafana ke 10.x (atau minimal 8.3.1+ untuk patch CVE-2021-43798).\n"
                "3. Aktifkan auth.proxy/oauth (Google/GitHub OAuth) dan disable basic login.\n"
                "4. IP allowlist + VPN untuk akses Grafana production.\n"
                "5. Audit datasource yang ter-konfigur - rotate kredensial DB kalau perlu."
            ),
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2021-43798",
                "https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/",
            ],
        ))
    finally:
        client.close()
    return findings
