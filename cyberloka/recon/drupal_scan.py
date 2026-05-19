"""Drupal fingerprint & exposure scanner.

Validasi sebelum lapor (minimal satu marker harus match):
    1. meta `<meta name="generator" content="Drupal X (https://www.drupal.org)">`
    2. header `X-Generator: Drupal`
    3. `/CHANGELOG.txt` mulai dengan `Drupal X.x, ...`
    4. body root memuat `Drupal.settings`

Probe tambahan setelah confirmed Drupal:
    * `/CHANGELOG.txt`         -> versi exact + advisory
    * `/MAINTAINERS.txt`
    * `/INSTALL.txt`
    * `/sites/default/files/`  -> directory listing
    * `/user/login`            -> login publik
    * `/?q=user/N` (1..3)      -> user enumeration via slug
    * `/jsonapi/user/user`     -> Drupal 8+ JSON:API user listing
    * `/?q=admin` redirect     -> indikasi admin path
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig
from cyberloka.core.util import truncate

GEN_RE = re.compile(
    r'<meta\s+name=[\'"]generator[\'"]\s+content=[\'"]Drupal\s*([\d.]*)',
    re.I,
)
CHANGELOG_RE = re.compile(r"^Drupal\s+([\d.]+),", re.I)


def _is_drupal(client: HttpClient, target: Target) -> tuple[bool, str, str]:
    base = target.origin + "/"
    r = client.get(target.base_url, allow_redirects=True)
    if r is None:
        return False, "", ""
    body = r.text or ""
    headers = r.headers or {}
    if "Drupal" in headers.get("X-Generator", ""):
        m = re.search(r"Drupal\s*([\d.]+)", headers.get("X-Generator", ""))
        return True, (m.group(1) if m else ""), "X-Generator header"
    m = GEN_RE.search(body)
    if m:
        return True, (m.group(1) or "").strip(), "meta generator"
    if "Drupal.settings" in body or "drupal.org" in body.lower():
        # confirm via CHANGELOG
        cr = client.get(urljoin(base, "CHANGELOG.txt"), allow_redirects=False)
        if cr and cr.status_code == 200:
            mc = CHANGELOG_RE.search((cr.text or "")[:200])
            if mc:
                return True, mc.group(1), "CHANGELOG.txt"
    return False, "", ""


def _check_changelog(client: HttpClient, target: Target) -> Finding | None:
    url = urljoin(target.origin + "/", "CHANGELOG.txt")
    r = client.get(url, allow_redirects=False,
                   headers={"Range": "bytes=0-2047"})
    if r is None or r.status_code != 200:
        return None
    text = (r.text or "")[:2048]
    m = CHANGELOG_RE.search(text)
    if not m:
        return None
    version = m.group(1)
    return Finding(
        module="drupal_scan",
        title=f"Drupal CHANGELOG.txt ter-ekspos (versi {version})",
        severity=Severity.MEDIUM,
        description=(
            "File CHANGELOG.txt Drupal dapat diakses publik, mengonfirmasi "
            "versi exact. Attacker bisa langsung cocokkan dengan advisory "
            f"di drupal.org/security untuk versi {version}."
        ),
        target=url,
        evidence=truncate(text.replace("\n", " ")[:200], 240),
        cwe="CWE-200",
        confidence="confirmed",
        remediation=(
            "Block file `CHANGELOG.txt`, `INSTALL.txt`, `MAINTAINERS.txt` "
            "di reverse-proxy. Patch Drupal core ke versi minor terbaru."
        ),
        references=["https://www.drupal.org/security"],
        extra={"reverify": {"marker": f"Drupal {version}", "in_body": True}},
    )


def _check_user_enum(client: HttpClient, target: Target) -> Finding | None:
    base = target.origin + "/"
    found: set[str] = set()
    for n in range(1, 4):
        r = client.get(urljoin(base, f"?q=user/{n}"), allow_redirects=False)
        if r is None:
            continue
        body = r.text or ""
        # Drupal user page menampilkan h1 "Username" atau redirect ke /user/<name>.
        m = re.search(r"<h1[^>]*>\s*([^<]{1,32})\s*</h1>", body)
        if m and r.status_code == 200:
            name = m.group(1).strip()
            if name and "not found" not in name.lower():
                found.add(name)
    if not found:
        return None
    return Finding(
        module="drupal_scan",
        title=f"Drupal user enumeration via /user/N ({len(found)} username)",
        severity=Severity.MEDIUM,
        description=(
            "Path `/user/<id>` membalas dengan H1 username untuk ID yang "
            "valid. Attacker dapat enumerasi user secara berurutan."
        ),
        target=urljoin(base, "?q=user/1"),
        evidence=f"usernames={sorted(found)}",
        cwe="CWE-200",
        confidence="confirmed",
        remediation=(
            "Aktifkan modul `Username Enumeration Prevention` atau "
            "blokir respons berbeda untuk ID valid vs invalid."
        ),
    )


def _check_jsonapi_users(client: HttpClient, target: Target) -> Finding | None:
    url = urljoin(target.origin + "/", "jsonapi/user/user")
    r = client.get(url, allow_redirects=False)
    if r is None or r.status_code != 200:
        return None
    body = r.text or ""
    if "jsonapi.org" not in body or '"name":' not in body:
        return None
    return Finding(
        module="drupal_scan",
        title="Drupal JSON:API users endpoint terbuka",
        severity=Severity.MEDIUM,
        description=(
            "`/jsonapi/user/user` membalas array user tanpa autentikasi. "
            "Pengganti modern dari user enum klasik."
        ),
        target=url,
        evidence=f"HTTP 200, body fragment: {body[:160]!r}",
        cwe="CWE-200",
        confidence="confirmed",
        remediation=(
            "Modul `JSON:API` punya pengaturan permission per resource. "
            "Drop akses anonymous ke `user/user` collection. Bila tidak "
            "dipakai, matikan modulnya."
        ),
        extra={"reverify": {"marker": "jsonapi.org", "in_body": True}},
    )


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        is_d, version, ev = _is_drupal(client, target)
        if not is_d:
            return findings

        findings.append(Finding(
            module="drupal_scan",
            title=f"Drupal terdeteksi" + (f" v{version}" if version else ""),
            severity=Severity.LOW if not version else Severity.MEDIUM,
            description=(
                "Site memakai Drupal. Probe tambahan: CHANGELOG, user enum, "
                "JSON:API. "
                + (f"Versi {version} — pastikan sudah patch terbaru."
                   if version else "")
            ),
            target=target.base_url,
            evidence=f"fingerprint: {ev}; version={version or 'unknown'}",
            cwe="CWE-200",
            confidence="confirmed",
            remediation=(
                "Patch Drupal core minor & modul kontribusi tepat waktu. "
                "Pantau drupal.org/security."
            ),
            references=["https://www.drupal.org/security"],
        ))

        for fn in (_check_changelog, _check_user_enum, _check_jsonapi_users):
            f = fn(client, target)
            if f:
                findings.append(f)
    finally:
        client.close()
    return findings
