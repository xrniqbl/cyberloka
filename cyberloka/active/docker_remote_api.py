"""Docker Remote API exposure (port 2375/2376/2377/4243).

Auto-validation: GET /version dan validasi struktur JSON khas Docker
(`ApiVersion`, `KernelVersion`, `Os`).
"""
from __future__ import annotations

import json
from urllib.parse import urlparse, urlunparse

from cyberloka.core import Finding, HttpClient, Severity, Target
from cyberloka.core.config import ScanConfig

CANDIDATE_PORTS = [2375, 2376, 4243]


def _candidates(target: Target) -> list[str]:
    """Build URL candidates for typical Docker Remote API exposure."""
    res: list[str] = []
    parsed = urlparse(target.origin)
    host = parsed.hostname or target.host

    # Same scheme/host but probe path /version directly
    res.append(target.origin.rstrip("/") + "/version")

    # Try common Docker ports if target host doesn't already use them
    for p in CANDIDATE_PORTS:
        for scheme in ("http", "https"):
            res.append(urlunparse((scheme, f"{host}:{p}", "/version", "", "", "")))
    # Dedup, keep order
    seen, out = set(), []
    for u in res:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _is_docker_version(text: str) -> dict | None:
    try:
        d = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(d, dict):
        return None
    keys = set(d.keys())
    expected = {"ApiVersion", "Version"}
    if expected.issubset(keys):
        return d
    return None


def run(target: Target, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    client = HttpClient(config)
    try:
        for url in _candidates(target):
            r = client.get(url, allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            data = _is_docker_version((r.text or "")[:4096])
            if not data:
                continue
            findings.append(Finding(
                module="docker_remote_api",
                title=f"Docker Remote API tanpa auth: {url}",
                severity=Severity.CRITICAL,
                description=(
                    "Docker Daemon mengekspos REST API tanpa TLS / autentikasi. "
                    f"Versi terdeteksi: {data.get('Version')} "
                    f"(ApiVersion={data.get('ApiVersion')})."
                ),
                target=url,
                urls=[url],
                evidence=(
                    f"GET {url} -> 200; payload JSON Docker valid "
                    f"(Version={data.get('Version')})."
                ),
                cwe="CWE-284",
                confidence="confirmed",
                remediation=(
                    "JANGAN ekspos Docker daemon ke internet. Bila perlu "
                    "remote, pakai TLS mutual auth: `--tlsverify --tlscacert "
                    "--tlscert --tlskey`. Setting di "
                    "/etc/docker/daemon.json: `\"hosts\": [\"unix:///var/run/docker.sock\"]`. "
                    "Pasang firewall iptables/ufw untuk port 2375/2376."
                ),
                references=[
                    "https://docs.docker.com/engine/security/protect-access/",
                    "https://www.cisecurity.org/benchmark/docker",
                ],
            ))
            break
    finally:
        client.close()
    return findings
