"""GitLab API exposure (unauthenticated /api/v4/users + projects).

Auto-validation: parse JSON response untuk struktur khas GitLab.
"""
from __future__ import annotations

import json
from urllib.parse import urljoin

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

PATHS = [
    "/api/v4/users?per_page=5",
    "/api/v4/projects?per_page=5&visibility=internal",
    "/api/v4/projects?per_page=5",
]


def _is_gitlab_user_list(text: str) -> bool:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return False
    if not isinstance(data, list) or not data:
        return False
    sample = data[0]
    if not isinstance(sample, dict):
        return False
    expected = {"id", "username", "name", "state"}
    return expected.issubset(sample.keys())


def _is_gitlab_project_list(text: str) -> bool:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return False
    if not isinstance(data, list) or not data:
        return False
    sample = data[0]
    if not isinstance(sample, dict):
        return False
    expected = {"id", "path_with_namespace", "default_branch"}
    return any(k in sample for k in ("path_with_namespace", "name_with_namespace")) \
        and "id" in sample


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for path in PATHS:
            url = urljoin(target.origin + "/", path.lstrip("/"))
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            is_users = "/users" in path and _is_gitlab_user_list(body)
            is_proj = "/projects" in path and _is_gitlab_project_list(body)
            if not (is_users or is_proj):
                continue
            kind = "user" if is_users else "project"
            findings.append(Finding(
                module="gitlab_unauth_api",
                title=f"GitLab API tanpa autentikasi: {path} ({kind} list)",
                severity=Severity.HIGH,
                description=(
                    "Instance GitLab mengembalikan daftar user/project tanpa "
                    "perlu autentikasi. Pengaturan GitLab default boleh untuk "
                    "GitLab.com publik, TAPI untuk instance internal harus "
                    "dimatikan via `application.users_visibility=private`."
                ),
                target=url,
                urls=[url],
                evidence=(
                    f"GET {url} -> 200; JSON response valid {kind} list "
                    f"({body[:120]}...)"
                ),
                cwe="CWE-200",
                confidence="confirmed",
                remediation=(
                    "Set `Sign-up enabled=false` di Admin -> Settings -> "
                    "General. Disable `Public access for unauthenticated users` "
                    "untuk users API. Pakai `Restricted visibility levels = "
                    "Public,Internal` agar internal projects tidak terlihat."
                ),
                references=[
                    "https://docs.gitlab.com/ee/security/restrict_user_creation.html",
                    "https://docs.gitlab.com/ee/api/users.html",
                ],
            ))
            if len(findings) >= 2:
                break
    finally:
        client.close()
    return findings
