"""403 Forbidden bypass via header/path tricks.

Auto-validation: minta path 403, lalu coba bypass; finding hanya muncul
bila bypass benar-benar mengembalikan 200/3xx + content yang berbeda.
"""
from __future__ import annotations

from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PROTECTED_PATHS = [
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/manage", "/console", "/dashboard", "/cpanel",
    "/.git/config", "/.env", "/server-status", "/server-info",
    "/api/admin", "/api/internal", "/internal",
]

# (label, callable returning kwargs for client.get)
TRICKS = [
    ("X-Original-URL header", lambda url: {"headers": {"X-Original-URL": _path_of(url)}}),
    ("X-Rewrite-URL header", lambda url: {"headers": {"X-Rewrite-URL": _path_of(url)}}),
    ("X-Forwarded-For 127.0.0.1", lambda url: {"headers": {"X-Forwarded-For": "127.0.0.1"}}),
    ("X-Forwarded-Host localhost", lambda url: {"headers": {"X-Forwarded-Host": "localhost"}}),
    ("X-Custom-IP-Authorization", lambda url: {"headers": {"X-Custom-IP-Authorization": "127.0.0.1"}}),
    ("Path: trailing-dot", None),
    ("Path: ;/", None),
    ("Path: %20", None),
    ("Path: //", None),
    ("Path: ..;/", None),
    ("Path: %09", None),
]


def _path_of(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).path or "/"


def _make_path_variations(base_url: str) -> list[tuple[str, str]]:
    """Return list of (label, mutated_url) for path-based bypass."""
    res: list[tuple[str, str]] = []
    for sep in (".", ";/", "%20", "%09", "..;/"):
        res.append((f"Path: trailing-{sep}", base_url.rstrip("/") + "/" + sep))
    res.append(("Path: //", base_url.rstrip("/") + "//"))
    res.append(("Path: %2e/", base_url.rstrip("/") + "/%2e/"))
    return res


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    seen: set[str] = set()
    try:
        for path in PROTECTED_PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            base = client.get(url, allow_redirects=False)
            if base is None or base.status_code not in (401, 403):
                continue
            base_status = base.status_code

            # Header tricks
            for label, builder in TRICKS:
                if builder is None:
                    continue
                kwargs = builder(url)
                r = client.get(url, allow_redirects=False, **kwargs)
                if r is None:
                    continue
                if _is_bypass(r, base_status):
                    key = f"{path}|{label}"
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(_finding(url, label, base_status, r.status_code))
                    break

            # Path tricks
            for label, mutated in _make_path_variations(url):
                r = client.get(mutated, allow_redirects=False)
                if r is None:
                    continue
                if _is_bypass(r, base_status):
                    key = f"{path}|{label}"
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(_finding(mutated, label, base_status, r.status_code))
                    break

            if len(findings) >= 4:
                break
    finally:
        client.close()
    return findings


def _is_bypass(r, base_status: int) -> bool:
    return r.status_code != base_status and r.status_code < 400


def _finding(url: str, label: str, base_status: int, new_status: int) -> Finding:
    return Finding(
        module="bypass_403",
        title=f"403 bypass berhasil via `{label}`",
        severity=Severity.HIGH,
        description=(
            f"Path yang awalnya dilindungi (HTTP {base_status}) menjadi "
            f"dapat diakses (HTTP {new_status}) hanya dengan trick `{label}`. "
            "Berarti reverse-proxy dan backend memiliki pemahaman path yang "
            "berbeda."
        ),
        target=url,
        urls=[url],
        evidence=f"baseline={base_status}; bypass via `{label}` -> {new_status}",
        cwe="CWE-284",
        confidence="confirmed",
        remediation=(
            "Pastikan reverse-proxy melakukan kanonik path SEBELUM authorisasi: "
            "decode URL, hapus '..', normalize trailing slash. Aktifkan strict "
            "matching pada policy ACL. Tolak header `X-Original-URL` / "
            "`X-Rewrite-URL` di edge."
        ),
        references=[
            "https://github.com/iamj0ker/bypass-403",
            "https://www.acunetix.com/vulnerabilities/web/x-original-url-header-bypass/",
        ],
    )
