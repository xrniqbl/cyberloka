"""Adminer / DBeaver-Web / SQLBuddy: deteksi + version check.

Adminer single-file PHP DB tool. Banyak insiden RCE karena versi lama (CVE).
Modul ini:
  1. Cek path umum Adminer (/adminer.php, /adminer/, /db.php, dst.)
  2. Validasi via title 'Adminer' atau body 'Adminer\\s+\\d+\\.\\d+'.
  3. Extract versi → bandingkan dengan list versi yang punya CVE diketahui.
  4. Coba submit halaman login dengan kredensial mysql default - validasi via
     redirect ke ?username=root atau cookie adminer_sid.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = (
    "/adminer.php", "/adminer/", "/admin.php", "/db.php",
    "/database.php", "/sql.php", "/manage/adminer.php",
    "/adminer-4.8.1.php", "/adminer-latest.php",
)

VERSION_RE = re.compile(r"Adminer\s+(\d+\.\d+(?:\.\d+)?)")
TITLE_RE = re.compile(r"<title>\s*([^<]+?)\s*-\s*Adminer", re.I)

# Versi yang punya CVE (CVE-2020-35572, CVE-2021-43008 dll)
KNOWN_VULN_BELOW = "4.8.1"


def _ver_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    base = target.base_url
    client = HttpClient(config)
    try:
        for path in PATHS:
            url = urljoin(base, path.lstrip("/"))
            r = client.get(url, allow_redirects=True)
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            m = VERSION_RE.search(body)
            t = TITLE_RE.search(body)
            if not (m or t or "name='auth[server]'" in body):
                continue

            version = m.group(1) if m else "unknown"
            outdated = False
            if version != "unknown":
                try:
                    if _ver_tuple(version) < _ver_tuple(KNOWN_VULN_BELOW):
                        outdated = True
                except Exception:
                    pass

            sev = Severity.HIGH if outdated else Severity.MEDIUM
            ev = [f"URL: {url}", f"Version: {version}"]
            if t:
                ev.append(f"Title: {t.group(0)[:80]}")

            # Coba login dengan default mysql cred
            login_ok = False
            for u, p in [("root", ""), ("root", "root"), ("root", "password")]:
                client.session.cookies.clear()
                resp = client.post(
                    url,
                    data={
                        "auth[driver]": "server",
                        "auth[server]": "127.0.0.1",
                        "auth[username]": u,
                        "auth[password]": p,
                        "auth[db]": "",
                    },
                    allow_redirects=False,
                )
                if resp is None:
                    continue
                cookies_set = [c.name.lower() for c in resp.cookies] if hasattr(resp, "cookies") else []
                if any("adminer" in c for c in cookies_set):
                    if resp.status_code in (301, 302, 303) and "username=" in (resp.headers.get("Location") or ""):
                        login_ok = True
                        ev.append(f"DEFAULT LOGIN OK: {u}:{p or '(empty)'} -> redirect with adminer_sid")
                        sev = Severity.CRITICAL
                        break
                    if resp.status_code == 200 and "auth[username]" not in (resp.text or "")[:5000]:
                        login_ok = True
                        ev.append(f"DEFAULT LOGIN OK: {u}:{p or '(empty)'} -> session created")
                        sev = Severity.CRITICAL
                        break

            findings.append(Finding(
                module="adminer_exposed",
                target=url,
                title=(
                    f"Adminer {version} terbuka publik"
                    + (" (versi rentan CVE)" if outdated else "")
                    + (" + login dengan default credentials BERHASIL" if login_ok else "")
                ),
                severity=sev,
                description=(
                    "Adminer adalah tool database web. Modul mengonfirmasi via "
                    "regex 'Adminer\\s+<version>' atau pola form auth[server]. "
                    + (
                        f"Versi {version} berada di bawah {KNOWN_VULN_BELOW} - "
                        "punya CVE yang diketahui (mis. CVE-2020-35572 SSRF)."
                        if outdated else ""
                    )
                    + (
                        "\n\nSelain itu, modul mencoba login ke MySQL local dengan kredensial "
                        "default umum dan BERHASIL - akses penuh ke database production."
                        if login_ok else ""
                    )
                ),
                evidence="\n".join(ev),
                cwe="CWE-1035" if outdated else "CWE-693",
                confidence="confirmed",
                urls=[url],
                remediation=(
                    "1. Hapus adminer.php dari webroot setelah dipakai (jangan disimpan permanen).\n"
                    "2. Bila perlu permanent: lindungi dengan IP allowlist + Basic Auth + 2FA.\n"
                    "3. Update Adminer ke versi terbaru (sekarang " + KNOWN_VULN_BELOW + ").\n"
                    "4. Bind MySQL/MariaDB ke 127.0.0.1, jangan 0.0.0.0."
                ),
                references=[
                    "https://www.adminer.org/en/security/",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35572",
                ],
            ))
    finally:
        client.close()
    return findings
